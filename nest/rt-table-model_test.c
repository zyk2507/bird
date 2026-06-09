/*
 *	BIRD -- Routing Table Model Tests
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test/birdtest.h"


#define BIRD_EXEC	"./bird"
#define BIRDC_EXEC	"./birdc"

#define ROUTE_KEEP	0x01
#define ROUTE_DROP	0x02

#define OUT_BUF_SIZE	16384

struct model_case {
  const char *name;
  const char *family;
  const char *indexed_table;
  const char *fib2_table;
  const char *indexed_copy_table;
  const char *fib2_copy_table;
  const char *indexed_static;
  const char *fib2_static;
  const char *indexed_pipe;
  const char *fib2_pipe;
  const char *keep_prefix;
  const char *drop_prefix;
};

struct test_env {
  char dir[128];
  char config[192];
  char ctl[192];
  char pidfile[192];
  char log[192];
  pid_t bird_pid;
};

static const struct model_case model_cases[] = {
  {
    .name = "IPv4",
    .family = "ipv4",
    .indexed_table = "t4_indexed",
    .fib2_table = "t4_fib2",
    .indexed_copy_table = "t4_indexed_copy",
    .fib2_copy_table = "t4_fib2_copy",
    .indexed_static = "s4_indexed",
    .fib2_static = "s4_fib2",
    .indexed_pipe = "p4_indexed",
    .fib2_pipe = "p4_fib2",
    .keep_prefix = "198.51.100.0/24",
    .drop_prefix = "203.0.113.0/24",
  },
  {
    .name = "IPv6",
    .family = "ipv6",
    .indexed_table = "t6_indexed",
    .fib2_table = "t6_fib2",
    .indexed_copy_table = "t6_indexed_copy",
    .fib2_copy_table = "t6_fib2_copy",
    .indexed_static = "s6_indexed",
    .fib2_static = "s6_fib2",
    .indexed_pipe = "p6_indexed",
    .fib2_pipe = "p6_fib2",
    .keep_prefix = "2001:db8:1::/48",
    .drop_prefix = "2001:db8:2::/48",
  },
};

static int
path_join(char *dst, size_t size, const char *dir, const char *name)
{
  int rv = snprintf(dst, size, "%s/%s", dir, name);
  return (rv > 0) && ((size_t) rv < size);
}

static int
command_status(int status)
{
  if (WIFEXITED(status))
    return WEXITSTATUS(status);

  if (WIFSIGNALED(status))
    return 128 + WTERMSIG(status);

  return 255;
}

static int
read_capture(int fd, char *out, size_t out_size)
{
  size_t pos = 0;

  if (out_size)
    out[0] = 0;

  for (;;)
  {
    char buf[512];
    ssize_t len = read(fd, buf, sizeof(buf));

    if (len < 0)
    {
      if (errno == EINTR)
	continue;

      return 0;
    }

    if (!len)
      break;

    if (out_size > 1)
    {
      size_t copy = MIN((size_t) len, out_size - pos - 1);
      memcpy(out + pos, buf, copy);
      pos += copy;
      out[pos] = 0;
    }
  }

  return 1;
}

static int
run_birdc(struct test_env *env, const char *cmd, char *out, size_t out_size)
{
  int fds[2];
  if (pipe(fds) < 0)
  {
    if (out_size)
      snprintf(out, out_size, "pipe: %s", strerror(errno));
    return 255;
  }

  pid_t pid = fork();
  if (pid < 0)
  {
    if (out_size)
      snprintf(out, out_size, "fork: %s", strerror(errno));
    close(fds[0]);
    close(fds[1]);
    return 255;
  }

  if (!pid)
  {
    close(fds[0]);
    dup2(fds[1], STDOUT_FILENO);
    dup2(fds[1], STDERR_FILENO);
    close(fds[1]);

    execl(BIRDC_EXEC, BIRDC_EXEC, "-s", env->ctl, cmd, NULL);
    _exit(127);
  }

  close(fds[1]);

  int ok = read_capture(fds[0], out, out_size);
  close(fds[0]);

  int status;
  while (waitpid(pid, &status, 0) < 0)
    if (errno != EINTR)
      return 255;

  return ok ? command_status(status) : 255;
}

static int
write_config(struct test_env *env, int include_drop_route)
{
  FILE *f = fopen(env->config, "w");
  if (!f)
  {
    bt_log("fopen(%s): %s", env->config, strerror(errno));
    return 0;
  }

  fprintf(f,
    "router id 192.0.2.1;\n"
    "log stderr all;\n"
    "\n");

  for (uint i = 0; i < ARRAY_SIZE(model_cases); i++)
  {
    const struct model_case *tc = &model_cases[i];

    fprintf(f,
      "%s table %s { model indexed; };\n"
      "%s table %s { model fib2; };\n"
      "%s table %s { model indexed; };\n"
      "%s table %s { model fib2; };\n"
      "\n",
      tc->family, tc->indexed_table,
      tc->family, tc->fib2_table,
      tc->family, tc->indexed_copy_table,
      tc->family, tc->fib2_copy_table);
  }

  for (uint i = 0; i < ARRAY_SIZE(model_cases); i++)
  {
    const struct model_case *tc = &model_cases[i];

    fprintf(f,
      "protocol static %s {\n"
      "  %s { table %s; import all; };\n"
      "  route %s blackhole;\n",
      tc->indexed_static, tc->family, tc->indexed_table, tc->keep_prefix);

    if (include_drop_route)
      fprintf(f, "  route %s blackhole;\n", tc->drop_prefix);

    fprintf(f,
      "}\n"
      "\n"
      "protocol static %s {\n"
      "  %s { table %s; import all; };\n"
      "  route %s blackhole;\n",
      tc->fib2_static, tc->family, tc->fib2_table, tc->keep_prefix);

    if (include_drop_route)
      fprintf(f, "  route %s blackhole;\n", tc->drop_prefix);

    fprintf(f,
      "}\n"
      "\n"
      "protocol pipe %s {\n"
      "  table %s;\n"
      "  peer table %s;\n"
      "  import none;\n"
      "  export all;\n"
      "}\n"
      "\n"
      "protocol pipe %s {\n"
      "  table %s;\n"
      "  peer table %s;\n"
      "  import none;\n"
      "  export all;\n"
      "}\n"
      "\n",
      tc->indexed_pipe, tc->indexed_table, tc->indexed_copy_table,
      tc->fib2_pipe, tc->fib2_table, tc->fib2_copy_table);
  }

  int rv = fclose(f);
  if (rv < 0)
    bt_log("fclose(%s): %s", env->config, strerror(errno));

  return !rv;
}

static int
setup_env(struct test_env *env)
{
  memset(env, 0, sizeof(*env));
  snprintf(env->dir, sizeof(env->dir), "/tmp/bird-rt-table-model-XXXXXX");

  if (!mkdtemp(env->dir))
  {
    bt_log("mkdtemp: %s", strerror(errno));
    return 0;
  }

  return
    path_join(env->config, sizeof(env->config), env->dir, "bird.conf") &&
    path_join(env->ctl, sizeof(env->ctl), env->dir, "bird.ctl") &&
    path_join(env->pidfile, sizeof(env->pidfile), env->dir, "bird.pid") &&
    path_join(env->log, sizeof(env->log), env->dir, "bird.log");
}

static int
start_bird(struct test_env *env)
{
  if (access(BIRD_EXEC, X_OK) < 0)
  {
    bt_log("%s: %s", BIRD_EXEC, strerror(errno));
    return 0;
  }

  if (access(BIRDC_EXEC, X_OK) < 0)
  {
    bt_log("%s: %s", BIRDC_EXEC, strerror(errno));
    return 0;
  }

  pid_t pid = fork();
  if (pid < 0)
  {
    bt_log("fork: %s", strerror(errno));
    return 0;
  }

  if (!pid)
  {
    int fd = open(env->log, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0)
    {
      dup2(fd, STDOUT_FILENO);
      dup2(fd, STDERR_FILENO);
      close(fd);
    }

    execl(BIRD_EXEC, BIRD_EXEC, "-f", "-c", env->config, "-s", env->ctl,
	  "-P", env->pidfile, NULL);
    _exit(127);
  }

  env->bird_pid = pid;
  return 1;
}

static int
wait_bird_ready(struct test_env *env)
{
  char out[OUT_BUF_SIZE];

  for (int i = 0; i < 50; i++)
  {
    if (!run_birdc(env, "show status", out, sizeof(out)))
      return 1;

    usleep(100000);
  }

  bt_log("BIRD did not become ready, last birdc output: %s", out);
  return 0;
}

static int
route_state(struct test_env *env, const struct model_case *tc, const char *table,
	    char *out, size_t out_size)
{
  char cmd[128];
  int rv = snprintf(cmd, sizeof(cmd), "show route table %s all", table);

  if ((rv < 0) || ((size_t) rv >= sizeof(cmd)))
  {
    snprintf(out, out_size, "show route command is too long");
    return -1;
  }

  rv = run_birdc(env, cmd, out, out_size);
  if (rv)
    return -1;

  int state = 0;
  if (strstr(out, tc->keep_prefix))
    state |= ROUTE_KEEP;
  if (strstr(out, tc->drop_prefix))
    state |= ROUTE_DROP;

  return state;
}

static int
check_model_pair(struct test_env *env, const struct model_case *tc,
		 const char *stage, const char *role,
		 const char *indexed_table, const char *fib2_table, int expected)
{
  char indexed_out[OUT_BUF_SIZE];
  char fib2_out[OUT_BUF_SIZE];
  int indexed_state = route_state(env, tc, indexed_table, indexed_out, sizeof(indexed_out));
  int fib2_state = route_state(env, tc, fib2_table, fib2_out, sizeof(fib2_out));
  int ok = (indexed_state == expected) && (fib2_state == expected) && (indexed_state == fib2_state);

  bt_assert_msg(ok,
    "%s %s %s route set: indexed=0x%x fib2=0x%x expected=0x%x",
    tc->name, stage, role, indexed_state, fib2_state, expected);

  if (!ok)
  {
    bt_log("%s output:\n%s", indexed_table, indexed_out);
    bt_log("%s output:\n%s", fib2_table, fib2_out);
  }

  return ok;
}

static int
check_all_tables(struct test_env *env, const struct model_case *tc,
		 const char *stage, int expected)
{
  int ok = 1;

  ok &= check_model_pair(env, tc, stage, "source tables",
			 tc->indexed_table, tc->fib2_table, expected);
  ok &= check_model_pair(env, tc, stage, "pipe destination tables",
			 tc->indexed_copy_table, tc->fib2_copy_table, expected);

  return ok;
}

static int
wait_all_tables(struct test_env *env, const struct model_case *tc,
		const char *stage, int expected)
{
  for (int i = 0; i < 50; i++)
  {
    char out[OUT_BUF_SIZE];
    int indexed = route_state(env, tc, tc->indexed_table, out, sizeof(out));
    int fib2 = route_state(env, tc, tc->fib2_table, out, sizeof(out));
    int indexed_copy = route_state(env, tc, tc->indexed_copy_table, out, sizeof(out));
    int fib2_copy = route_state(env, tc, tc->fib2_copy_table, out, sizeof(out));

    if ((indexed == expected) && (fib2 == expected) &&
	(indexed_copy == expected) && (fib2_copy == expected))
      return check_all_tables(env, tc, stage, expected);

    usleep(100000);
  }

  return check_all_tables(env, tc, stage, expected);
}

static int
wait_all_cases(struct test_env *env, const char *stage, int expected)
{
  int ok = 1;

  for (uint i = 0; i < ARRAY_SIZE(model_cases); i++)
    ok &= wait_all_tables(env, &model_cases[i], stage, expected);

  return ok;
}

static void
stop_bird(struct test_env *env)
{
  if (env->bird_pid <= 0)
    return;

  char out[OUT_BUF_SIZE];
  run_birdc(env, "down", out, sizeof(out));

  for (int i = 0; i < 50; i++)
  {
    int status;
    pid_t rv = waitpid(env->bird_pid, &status, WNOHANG);
    if (rv == env->bird_pid)
    {
      env->bird_pid = 0;
      return;
    }

    if ((rv < 0) && (errno != EINTR))
      break;

    usleep(100000);
  }

  kill(env->bird_pid, SIGTERM);
  while (waitpid(env->bird_pid, NULL, 0) < 0)
    if (errno != EINTR)
      break;

  env->bird_pid = 0;
}

static void
cleanup_env(struct test_env *env)
{
  unlink(env->config);
  unlink(env->ctl);
  unlink(env->pidfile);
  unlink(env->log);

  if (env->dir[0])
    rmdir(env->dir);
}

static int
t_table_model_consistency(void)
{
  struct test_env env;
  char out[OUT_BUF_SIZE];
  int ok = setup_env(&env);

  if (ok)
    ok = write_config(&env, 1);

  if (ok)
    ok = start_bird(&env);

  if (ok)
    ok = wait_bird_ready(&env);

  if (ok)
    ok = wait_all_cases(&env, "initial import and pipe feed",
			ROUTE_KEEP | ROUTE_DROP);

  if (ok)
    ok = write_config(&env, 0);

  if (ok)
  {
    int rv = run_birdc(&env, "configure", out, sizeof(out));
    bt_assert_msg(!rv, "reconfigure after route removal: status=%d output=%s", rv, out);
    ok = !rv;
  }

  if (ok)
    ok = wait_all_cases(&env, "after static route withdrawal", ROUTE_KEEP);

  stop_bird(&env);
  cleanup_env(&env);

  return ok && bt_suite_result;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_table_model_consistency,
    "Comparing indexed and fib2 table model behavior for IPv4 and IPv6");

  return bt_exit_value();
}

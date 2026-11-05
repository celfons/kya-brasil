# Tests only: runs a command in a pseudo-terminal (a real TTY for readline), types each answer when the output has
# been quiet for a moment, and reports whether the process exited by itself.
# usage: python3 -I pty-run.py <cwd> <timeout-s> <answers separated by |> <cmd...>
import json, os, pty, select, sys, time

cwd, limit, answers, cmd = sys.argv[1], float(sys.argv[2]), sys.argv[3].split("|") if sys.argv[3] else [], sys.argv[4:]
pid, fd = pty.fork()
if pid == 0:
    os.chdir(cwd)
    os.execvp(cmd[0], cmd)
out, sent, start, last = b"", 0, time.time(), time.time()
status, exited = None, False
while time.time() - start < limit:
    r, _, _ = select.select([fd], [], [], 0.2)
    if r:
        try:
            d = os.read(fd, 4096)
        except OSError:
            d = b""
        if d:
            out += d
            last = time.time()
    done, st = os.waitpid(pid, os.WNOHANG)
    if done:
        status, exited = st, True
        break
    if sent < len(answers) and time.time() - last > 1.0:
        os.write(fd, (answers[sent] + "\r").encode())
        sent += 1
        last = time.time()
if not exited:
    os.kill(pid, 9)
    os.waitpid(pid, 0)
print(json.dumps({"exited": exited, "code": os.waitstatus_to_exitcode(status) if exited else None, "sent": sent, "tail": out.decode(errors="replace")[-600:]}))

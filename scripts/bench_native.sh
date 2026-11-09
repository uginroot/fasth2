run(){ out=$(h2load $3 http://127.0.0.1:$2$4 2>&1)
  rps=$(echo "$out" | grep -E "^finished" | sed -E 's/.*, ([0-9.]+) req\/s.*/\1/')
  ok=$(echo "$out" | grep -oE "[0-9]+ succeeded")
  lat=$(echo "$out" | grep "time for request" | awk '{print "mean="$6" max="$5}')
  printf "%-9s %-6s %-24s rps=%-10s %s %s\n" "$1" "$4" "$3" "$rps" "$lat" "$ok"; }
for p in 8083 8085 8086 8082; do h2load -n 50000 -c 10 -m 10 http://127.0.0.1:$p/ >/dev/null; done
echo "### CPU-only /"
for sc in "-n 30000 -c 1 -m 1" "-n 300000 -c 10 -m 10" "-n 600000 -c 100 -m 100" "-n 600000 -c 500 -m 20"; do
  for r in 1 2 3; do run Go1.27 8083 "$sc" /; run inline 8085 "$sc" /; run async 8086 "$sc" /; run Rust 8082 "$sc" /; done; echo
done
echo "### /sleep 1ms"
for sc in "-n 20000 -c 1 -m 100" "-n 100000 -c 10 -m 100" "-n 200000 -c 100 -m 100"; do
  for r in 1 2; do run Go1.27 8083 "$sc" /sleep; run inline 8085 "$sc" /sleep; run async 8086 "$sc" /sleep; run Rust 8082 "$sc" /sleep; done; echo
done
ps -o rss,comm -C server127,fasth2server,rsh2
echo FIN

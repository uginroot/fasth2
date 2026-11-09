run(){ out=$(h2load $3 $2 2>&1)
  rps=$(echo "$out" | grep -E "^finished" | sed -E 's/.*, ([0-9.]+) req\/s.*/\1/')
  ok=$(echo "$out" | grep -oE "[0-9]+ succeeded"); codes=$(echo "$out" | grep -oE "[0-9]+ 2xx")
  lat=$(echo "$out" | grep "time for request" | awk '{print "mean="$6" max="$5}')
  printf "%-14s %-26s %-22s rps=%-10s %s %s %s\n" "$1" "${2#*//*/}" "$3" "$rps" "$lat" "$ok" "$codes"; }
for u in http://127.0.0.1:8090/ http://127.0.0.1:8091/ https://127.0.0.1:8092/ https://127.0.0.1:8093/; do h2load -n 30000 -c 10 -m 10 $u >/dev/null; done
for path in "/" "/users/5" "/sleep"; do
 for sc in "-n 200000 -c 10 -m 10" "-n 200000 -c 100 -m 100"; do
  [ "$path" = "/sleep" ] && sc="${sc/-m 10 /-m 100 }"
  for r in 1 2; do
   run "h2c net/http" "http://127.0.0.1:8090$path" "$sc"; run "h2c fasth2" "http://127.0.0.1:8091$path" "$sc"
   run "tls net/http" "https://127.0.0.1:8092$path" "$sc"; run "tls fasth2" "https://127.0.0.1:8093$path" "$sc"
  done; echo
 done
done
ps -o rss,args -C muxapp
echo FIN

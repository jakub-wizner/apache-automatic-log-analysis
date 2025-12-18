#!/bin/bash


ITERATIONS=100
HOST="http://192.168.1.201"

echo "Generating Apache logs with various HTTP status codes..."

for i in $(seq 1 $ITERATIONS); do
  
  curl -s -o /dev/null "$HOST/"
  
  curl -s -o /dev/null "$HOST/page-$RANDOM"
  curl -s -o /dev/null "$HOST/missing.html"
  
  curl -s -o /dev/null "$HOST/.htaccess"
  curl -s -o /dev/null "$HOST/.git/config"
  
  curl -s -o /dev/null "$HOST/" -H "Host: "
  
  curl -s -o /dev/null "$HOST/icons"
  
  curl -s -o /dev/null -A "Mozilla/5.0" "$HOST/"
  curl -s -o /dev/null -A "Googlebot" "$HOST/"
  
  sleep 0.1

  if [ $((i % 10)) -eq 0 ]; then
    echo "Processed $i iterations..."
  fi
done

echo "Done! Check your logs"

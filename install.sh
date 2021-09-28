git clone https://github.com/3digitdev/poly.git ./poly
cd poly

if [ -f "/usr/bin/poly"]; then
  cd .. && rm -rf ./poly
  >&2 echo "ERROR: /usr/bin/poly already exists; exiting"
  exit(1)
else
  cp poly /usr/bin/poly
fi
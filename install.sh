git clone https://github.com/3digitdev/poly.git ./poly

if [ -f "/usr/bin/poly" ]; then
  rm -rf poly
  >&2 echo "ERROR: /usr/bin/poly already exists; exiting"
  exit 1
else
  cp poly/poly /usr/bin/poly
  rm -rf poly/
  rm install.sh
  exit 0
fi
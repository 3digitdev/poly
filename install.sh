BIN_TARGET="/usr/local/bin/poly"

# -------------------------------------------------

# Proper cleanup if something happens
# Unfortunately we can't undo PIP packages easily if they installed...
function cleanup() {
  sudo cp poly/old_poly "${BIN_TARGET}" 2>/dev/null || true
  rm -rf poly/ 2>/dev/null || true
  >&2 echo "Something went wrong - exiting without changes"
  exit 255
}

trap 'cleanup' SIGINT SIGTERM ERR

# -------------------------------------------------

# Move somewhere with known write-access first, or bail
cd ~ || exit
git clone https://github.com/3digitdev/poly.git ./poly

# Backup the app so they don't lose what's there if the upgrade fails
if command -v poly; then
  # Use their install location instead of our own!
  BIN_TARGET=$(command -v poly)
  sudo cp "${BIN_TARGET}" ./poly/old_poly
  echo "Detected ${BIN_TARGET} -- this will be overwritten!"
fi

# Make sure they are okay with dependencies...
echo "poly needs to install the following python packages to function:"
cat poly/requirements.txt
read -p "Do you want to continue? (y/n) " -r
if [[ $REPLY =~ ^[Yy]$ ]]; then
  # Get started with install!
  echo "Installing dependencies..."
  /usr/bin/python3 -m pip install --user -r poly/requirements.txt
  # This will overwrite whatever is there -- handy for upgrades
  # ...not so handy if someone steals my project name :)
  sudo cp poly/poly ${BIN_TARGET}
  sudo chmod +x ${BIN_TARGET}
  rm -rf poly/
  echo "poly installed to ${BIN_TARGET}"
  exit 0
else
  rm -rf poly/
  >&2 echo "Exiting without changes"
  exit 1
fi
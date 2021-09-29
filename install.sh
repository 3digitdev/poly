git clone https://github.com/3digitdev/poly.git ./poly

if [ -f "/usr/bin/poly" ]; then
    rm -rf poly
    >&2 echo "ERROR: /usr/bin/poly already exists - exiting"
    exit 1
else
    echo "Poly needs to install the following python packages to function:"
    cat poly/requirements.txt
    read -p "Do you want to continue? (y/n) " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Installing dependencies..."
        /usr/bin/python3 -m pip install --user -r poly/requirements.txt
        sudo cp poly/poly /usr/bin/poly
        sudo chmod +x /usr/bin/poly
        rm -rf poly/
        echo "Poly installed."
        exit 0
    fi
    rm -rf poly/
    echo "Exiting without changes"
    exit 1
fi

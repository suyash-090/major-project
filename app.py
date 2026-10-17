import os

from breachbox import create_app

app = create_app()

if __name__ == "__main__":
    # host="0.0.0.0" matters once this runs inside Docker, 127.0.0.1
    # would only be reachable from inside the container itself.
    # debug is off by default. Flask's debugger can run code from the
    # browser when a page errors, which we don't want during the demo or
    # the isolation test. Set BREACHBOX_DEBUG=1 locally if you need it.
    debug = os.environ.get("BREACHBOX_DEBUG") == "1"
    app.run(host="0.0.0.0", port=5000, debug=debug)

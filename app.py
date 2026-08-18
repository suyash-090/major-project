from breachbox import create_app

app = create_app()

if __name__ == "__main__":
    # host="0.0.0.0" matters once this runs inside Docker, 127.0.0.1
    # would only be reachable from inside the container itself.
    # debug=True stays on for local development, turn it off before
    # anything resembling the Week 8 isolation test.
    app.run(host="0.0.0.0", port=5000, debug=True)

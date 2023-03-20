from flask import Flask, Response, render_template, request, send_from_directory, jsonify, abort, send_file
from helper import get_phishing_result
from werkzeug.utils import secure_filename
from datetime import date
import time
import json
import os


app = Flask(__name__)
app.secret_key = os.urandom(12).hex()

default_screenshot_width = 1920
default_screenshot_height = 1080


@app.route('/')
def home():
    # update_stats('visits')
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("About.html")

@app.route('/check', methods=['GET', 'POST'])
def check():
    # update_stats('visits')
    if request.method == "POST":
        target_url = request.json['target']
        result = get_phishing_result(target_url=target_url)
        return jsonify(result)
    target_url = request.args.get("target")
    return render_template('check.html', target=target_url)

# @app.route("/listen")
# def listen():

#     def respond_to_client():
#         while True:
#             # stats = get_stats()
#             _data = json.dumps(
#                 {"visits": stats['visits'], "checked": stats['checked'], "phished": stats['phished']})
#             yield f"id: 1\ndata: {_data}\nevent: stats\n\n"
#             time.sleep(0.5)

#     return Response(respond_to_client(), mimetype='text/event-stream')

@app.route("/img_land")
def imgland():
    return send_file(r'Assets/landing.png', mimetype='image/png')

@app.route("/img_home_vector")
def imghome():
    return send_file(r'Assets/home.png', mimetype='image/png')

@app.route("/img_res")
def imgres():
    return send_file(r'Assets/res.png', mimetype='image/png')

@app.route("/screenshot")
def screenshot():
    query = request.args
    if query and query.get("target"):
        target_url = query.get("target")
        today_date = date.today()

        width = default_screenshot_width
        height = default_screenshot_height

        if query.get("width") and query.get("height"):
            width = int(query.get("width"))
            height = int(query.get("height"))

        # ss_file_name = secure_filename(f"{target_url}-{today_date}-{width}x{height}.png")
        # ss_file_path = os.path.join(screenshot_dir, ss_file_name)

        # if os.path.exists(ss_file_path):
            # return send_from_directory(screenshot_dir, path=ss_file_name)

        # return capture_screenshot(target_url=target_url, filename=ss_file_name, size=(width, height))
    abort(404)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8880, debug=True)

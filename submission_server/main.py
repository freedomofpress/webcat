import os
from enum import StrEnum
import pymysql
import awsgi
from flask import Flask, jsonify, request, abort
from werkzeug.exceptions import MethodNotAllowed, UnsupportedMediaType, HTTPException

app = Flask(__name__)

class ActionTypeValue(StrEnum):
    ADD = "ADD"
    MODIFY = "MODIFY"
    DELETE = "DELETE"

DB_HOST = os.getenv("DB_HOST")
DB_PORT = int(os.getenv("DB_PORT"))
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")

def initialize_database():
    conn = pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        cursorclass=pymysql.cursors.DictCursor
    )

    with conn.cursor() as cursor:
        cursor.execute("SHOW DATABASES LIKE %s;", (DB_NAME,))
        database_exists = cursor.fetchone() is not None

    if not database_exists:
        with conn.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE `{DB_NAME}`;")
            conn.select_db(DB_NAME)
            print(f"Database '{DB_NAME}' created.")

            with open("/var/task/schema.sql", "r") as schema_file:
                schema_sql = schema_file.read()
                for statement in schema_sql.split(';'):
                    if statement.strip():
                        cursor.execute(statement)
                print("Schema created")
                conn.commit()
    else:
        # Database exists, connect to it directly
        conn.select_db(DB_NAME)
    conn.close()

initialize_database()

def get_db_connection():
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        port=DB_PORT,
        password=DB_PASSWORD,
        database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor
    )

@app.route('/submission', methods=['POST'])
def post_submission():
    data = request.get_json()
    
    if not all(key in data for key in ("fqdn", "action")):
        return jsonify({"status": "KO", "Error": "Missing the `fqdn` or `action` keys."}), 400
    
    fqdn_input = data["fqdn"]
    type_input = data["action"].upper()

    if type_input not in ActionTypeValue.__members__.values():
        return jsonify({"status": "KO", "Error": "`action` value is not in [`ADD`, `MODIFY`, `DELETE`]"}), 400

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO submissions (submitted_fqdn, type) VALUES (%s, %s);",
                (fqdn_input, type_input)
            )
            conn.commit()
            submission_id = cursor.lastrowid
        return jsonify({"status": "OK", "id": submission_id}), 200
    except Exception as e:
        print(e)
        return jsonify({"status": "KO", "message": "A server error as occurred, contact and administrator."}), 500
    finally:
        conn.close()

@app.route('/submission', methods=['GET'])
def get_total_submissions():
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(id) as total_submissions FROM submissions;")
            result = cursor.fetchone()
        return jsonify({"status": "OK", "total_submissions": result["total_submissions"]}), 200
    except Exception as e:
        print(e)
        return jsonify({"status": "KO", "message": "A server error as occurred, contact and administrator."}), 500
    finally:
        conn.close()

@app.route('/submission/<int:submission_id>', methods=['GET'])
def get_submission(submission_id):
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # Fetch submission details
            cursor.execute("""
                SELECT id, submitted_fqdn, fqdn, type, timestamp, status_id, status_timestamp,
                (SELECT value FROM statuses WHERE id = submissions.status_id) AS status_value
                FROM submissions WHERE id = %s
            """, (submission_id,))
            submission = cursor.fetchone()
            
            if not submission:
                return jsonify({"status": "KO", "Error": "Submission with the id provided not found."}), 404

            cursor.execute("""
                SELECT status_id, timestamp FROM status_changes WHERE submission_id = %s
            """, (submission_id,))
            status_log = cursor.fetchall()

        return jsonify({
            "status": "OK",
            "id": submission["id"],
            "fqdn": submission["fqdn"],
            "type": submission["type"],
            "status": submission["status_value"],
            "log": status_log
        }), 200
    except Exception as e:
        print(e)
        return jsonify({"status": "KO", "message": "A server error as occurred, contact and administrator."}), 500
    finally:
        conn.close()

@app.errorhandler(MethodNotAllowed)
def method_not_allowed(e):
    print(e)
    return jsonify({"status": "KO", "message": "Method not allowed."}), 405

@app.errorhandler(UnsupportedMediaType)
def handle_unsupported_media_type(e):
    print(e)
    return jsonify({"status": "KO", "message": "Unsupported media type"}), 415

@app.errorhandler(HTTPException)
def handle_http_exception(e):
    print(e)
    return jsonify({"status": "KO", "message": "An HTTP exception has occurred, check the response code."}), e.code

@app.errorhandler(Exception)
def handle_exception(e):
    print(e)
    return jsonify({"status": "KO", "message": "An unexpected error occurred"}), 500

if __name__ == "__main__":
    app.run()

def lambda_handler(event, context):
    # See https://github.com/slank/awsgi/issues/73
    # TODO update to a more modern lib that as payload 2.0 support and is updated
    if 'httpMethod' not in event:
        event['httpMethod'] = event['requestContext']['http']['method']
        event['path'] = event['requestContext']['http']['path']
        event['queryStringParameters'] = event.get('queryStringParameters', {})
    return awsgi.response(app, event, context)

"""Private file attachments for Iran Change Mini Chat."""

import os
import uuid
from pathlib import Path
from urllib.parse import quote

import requests
from flask import jsonify, request, Response, stream_with_context
from werkzeug.utils import secure_filename


BUCKET = "iran-change-documents"
MAX_FILE_BYTES = 20 * 1024 * 1024


def install_minichat_file_routes(
    app, db_request, admin_authorized, telegram_user
):
    def storage_settings():
        url = os.environ.get("SUPABASE_URL", "").rstrip("/")
        key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
        if not url or not key:
            raise RuntimeError("Supabase storage not configured")
        return url, key

    def storage_url(path):
        url, _ = storage_settings()
        return (
            url + "/storage/v1/object/"
            + BUCKET + "/" + quote(path, safe="/")
        )

    def storage_headers(content_type=None):
        _, key = storage_settings()
        headers = {
            "apikey": key,
            "Authorization": "Bearer " + key,
        }
        if content_type:
            headers["Content-Type"] = content_type
        return headers

    def get_thread(thread_id):
        rows = db_request(
            "GET", "iran_chat_threads",
            {
                "select": "thread_id,agreement_id,participant_id",
                "thread_id": f"eq.{thread_id}",
                "limit": 1,
            }
        )
        if not rows:
            return None, None

        agreements = db_request(
            "GET", "iran_chat_agreements",
            {
                "select": "agreement_id,status",
                "agreement_id": f"eq.{rows[0]['agreement_id']}",
                "limit": 1,
            }
        )
        return rows[0], agreements[0] if agreements else None

    def get_message(message_id):
        rows = db_request(
            "GET", "iran_chat_messages",
            {
                "select": (
                    "message_id,thread_id,message_type,"
                    "message_text,file_reference"
                ),
                "message_id": f"eq.{message_id}",
                "limit": 1,
            }
        )
        return rows[0] if rows else None

    def file_response(message):
        path = message.get("file_reference")
        if (
            message.get("message_type") != "file"
            or not isinstance(path, str)
            or not path
            or path.startswith("/")
            or ".." in Path(path).parts
        ):
            return jsonify({"error": "File not found"}), 404

        try:
            upstream = requests.get(
                storage_url(path),
                headers=storage_headers(),
                stream=True,
                timeout=(10, 90),
            )

            if upstream.status_code != 200:
                upstream.close()
                return jsonify({"error": "File unavailable"}), 404

            filename = (
                str(message.get("message_text") or "document")
                .replace("\r", "")
                .replace("\n", "")
                .replace("/", "_")
                .replace("\\", "_")
            )[:180]

            def chunks():
                try:
                    for chunk in upstream.iter_content(65536):
                        if chunk:
                            yield chunk
                finally:
                    upstream.close()

            response = Response(
                stream_with_context(chunks()),
                content_type="application/octet-stream",
            )
            response.headers["Content-Disposition"] = (
                "attachment; filename=\"download\"; "
                "filename*=UTF-8''" + quote(filename)
            )
            response.headers["Cache-Control"] = "no-store, private"
            response.headers["X-Content-Type-Options"] = "nosniff"
            return response

        except (requests.RequestException, RuntimeError):
            app.logger.exception("MiniChat file download failed")
            return jsonify({"error": "Storage unavailable"}), 503

    @app.route("/minichat/api/upload", methods=["POST"])
    def participant_upload():
        uid = telegram_user()
        if uid is None:
            return jsonify({"error": "Unauthorized"}), 401

        try:
            thread_id = int(request.form.get("thread_id", "0"))
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid thread"}), 400

        if thread_id <= 0:
            return jsonify({"error": "Invalid thread"}), 400

        uploaded = request.files.get("file")
        if uploaded is None or not uploaded.filename:
            return jsonify({"error": "No file selected"}), 400

        if (
            request.content_length is not None
            and request.content_length > MAX_FILE_BYTES + 1024 * 1024
        ):
            return jsonify({"error": "File too large"}), 413

        try:
            thread, agreement = get_thread(thread_id)
            if not thread or not agreement:
                return jsonify({"error": "Thread not found"}), 404

            if int(thread["participant_id"]) != uid:
                return jsonify({"error": "Thread not found"}), 404

            if agreement["status"] != "active":
                return jsonify({"error": "Agreement is closed"}), 409

            content = uploaded.stream.read(MAX_FILE_BYTES + 1)
            if not content:
                return jsonify({"error": "Empty file"}), 400
            if len(content) > MAX_FILE_BYTES:
                return jsonify({"error": "File too large"}), 413

            original_name = (
                uploaded.filename.replace("\r", "")
                .replace("\n", "")
                .replace("/", "_")
                .replace("\\", "_")
            )[:180]

            safe_name = secure_filename(original_name)
            suffix = Path(safe_name).suffix.lower()[:12]
            object_path = (
                f"agreements/{thread['agreement_id']}/"
                f"threads/{thread_id}/{uuid.uuid4().hex}{suffix}"
            )

            response = requests.post(
                storage_url(object_path),
                headers={
                    **storage_headers("application/octet-stream"),
                    "x-upsert": "false",
                },
                data=content,
                timeout=(10, 90),
            )
            response.raise_for_status()

            try:
                saved = db_request(
                    "POST", "iran_chat_messages",
                    payload=[{
                        "thread_id": thread_id,
                        "sender_role": "participant",
                        "message_type": "file",
                        "message_text": original_name,
                        "file_reference": object_path,
                    }],
                    prefer="return=representation",
                )
                if not saved:
                    raise ValueError("Message was not saved")
            except Exception:
                try:
                    requests.delete(
                        storage_url(object_path),
                        headers=storage_headers(),
                        timeout=15,
                    )
                except requests.RequestException:
                    app.logger.exception("Orphan file cleanup failed")
                raise

            return jsonify({"message": saved[0]}), 201

        except (requests.RequestException, RuntimeError, ValueError,
                TypeError, KeyError, IndexError):
            app.logger.exception("MiniChat upload failed")
            return jsonify({"error": "File upload failed"}), 503

    @app.route(
        "/minichat/api/files/<int:message_id>",
        methods=["GET"]
    )
    def participant_file(message_id):
        uid = telegram_user()
        if uid is None:
            return jsonify({"error": "Unauthorized"}), 401

        try:
            message = get_message(message_id)
            if not message:
                return jsonify({"error": "File not found"}), 404

            thread, agreement = get_thread(int(message["thread_id"]))
            if not thread or not agreement:
                return jsonify({"error": "File not found"}), 404
            if int(thread["participant_id"]) != uid:
                return jsonify({"error": "File not found"}), 404

            return file_response(message)

        except (requests.RequestException, RuntimeError, ValueError,
                TypeError, KeyError):
            app.logger.exception("Participant file access failed")
            return jsonify({"error": "File unavailable"}), 503

    @app.route(
        "/admin/minichat/files/<int:message_id>",
        methods=["GET", "OPTIONS"]
    )
    def admin_file(message_id):
        if request.method == "OPTIONS":
            return "", 204

        if not admin_authorized():
            return jsonify({"error": "Unauthorized"}), 401

        try:
            message = get_message(message_id)
            if not message:
                return jsonify({"error": "File not found"}), 404

            thread, agreement = get_thread(int(message["thread_id"]))
            if not thread or not agreement:
                return jsonify({"error": "File not found"}), 404

            return file_response(message)

        except (requests.RequestException, RuntimeError, ValueError,
                TypeError, KeyError):
            app.logger.exception("Admin file access failed")
            return jsonify({"error": "File unavailable"}), 503

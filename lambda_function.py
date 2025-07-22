import json
from passlib.hash import pbkdf2_sha256

def lambda_handler(event, context):
    try:
        body = json.loads(event.get('body', '{}'))

        password = body.get("password", "")
        stored_hash = body.get("hash", "")
        action = body.get("action", "verify")  # "verify" or "hash"

        if not password:
            return {
                'statusCode': 400,
                'body': json.dumps("Missing 'password' in request body 5:50PM.")
            }

        # Handle password hashing
        if action == "hash":
            hashed = pbkdf2_sha256.hash(password)
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'hashed_password': hashed,
                    'message': 'Password hashed successfully'
                })
            }

        # Handle password verification
        elif action == "verify":
            if not stored_hash:
                return {
                    'statusCode': 400,
                    'body': json.dumps("Missing 'hash' for verification.")
                }

            is_match = pbkdf2_sha256.verify(password, stored_hash)
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'match': is_match,
                    'message': 'Password matches' if is_match else 'Password does not match'
                })
            }

        else:
            return {
                'statusCode': 400,
                'body': json.dumps("Invalid action. Use 'hash' or 'verify'.")
            }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error: {str(e)}")
        }


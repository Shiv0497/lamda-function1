import json
from passlib.hash import pbkdf2_sha256

def lambda_handler(event, context):
    # Sample input from event
    try:
        body = json.loads(event.get('body', '{}'))
        user_input_password = body.get("password", "")
        stored_hash = body.get("hash", "")

        if not user_input_password or not stored_hash:
            return {
                'statusCode': 400,
                'body': json.dumps("Password or hash missing.")
            }

        # Verify password
        is_match = pbkdf2_sha256.verify(user_input_password, stored_hash)

        return {
            'statusCode': 200,
            'body': json.dumps({
                'match': is_match,
                'message': 'Password verification successful' if is_match else 'Password does not match'
            })
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error: {str(e)}")
        }

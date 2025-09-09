import sqlite3

def cleanup_incomplete_users():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Delete users who are not phone verified
    c.execute("DELETE FROM users WHERE phone_verified = 0")
    
    # Also clean up any related OTP entries
    c.execute("DELETE FROM otps")
    
    conn.commit()
    conn.close()
    print("Incomplete users and OTPs cleaned up successfully!")

if __name__ == "__main__":
    cleanup_incomplete_users()
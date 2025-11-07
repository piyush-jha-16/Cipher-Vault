"""
Database migration script to add salt column to users table
Run this script once to update your existing database
"""
import sqlite3
from utils.encryption import generate_salt

def migrate_database():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Check if salt column exists
    cursor.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]
    
    if 'salt' not in columns:
        print("Adding 'salt' column to users table...")
        cursor.execute("ALTER TABLE users ADD COLUMN salt TEXT")
        
        # Generate salt for existing users
        cursor.execute("SELECT id FROM users")
        users = cursor.fetchall()
        
        for user in users:
            user_id = user[0]
            salt = generate_salt()
            cursor.execute("UPDATE users SET salt = ? WHERE id = ?", (salt, user_id))
        
        conn.commit()
        print(f"✓ Successfully added salt to {len(users)} existing user(s)")
    else:
        print("✓ Database already up to date - salt column exists")
    
    conn.close()
    print("\n✓ Migration completed successfully!")
    print("\nIMPORTANT NOTES:")
    print("1. All existing passwords in the database are still encrypted with bcrypt")
    print("2. Users must re-save their passwords to use the new Fernet encryption")
    print("3. Old passwords will continue to work but won't be viewable until re-saved")

if __name__ == "__main__":
    print("=" * 60)
    print("DATABASE MIGRATION SCRIPT")
    print("=" * 60)
    print("\nThis script will:")
    print("- Add 'salt' column to users table")
    print("- Generate unique salt for each existing user")
    print("\nStarting migration...\n")
    
    try:
        migrate_database()
    except Exception as e:
        print(f"\n✗ Error during migration: {e}")
        print("Please check your database and try again.")

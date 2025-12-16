# database.py (V4.1 - The Friend System Update)

import sqlite3
import logging
import random
from typing import List, Tuple, Optional

logger = logging.getLogger('SMPDatabase')


class SMPDatabase:
    def __init__(self, db_path='smp_data_v4.db'):  # 建议使用新文件名以避免冲突
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        # --- 用户表 (不变) ---
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, salt TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # --- 群组表 (不变) ---
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT, group_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
                created_by_id TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # --- 群组成员表 (不变) ---
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS group_members (
                group_id TEXT NOT NULL, user_id TEXT NOT NULL,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (group_id, user_id)
            )
        ''')
        # --- V4 新增：好友关系表 ---
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS friends (
                user_id TEXT NOT NULL,
                friend_id TEXT NOT NULL,
                PRIMARY KEY (user_id, friend_id),
                FOREIGN KEY (user_id) REFERENCES users(user_id),
                FOREIGN KEY (friend_id) REFERENCES users(user_id)
            )
        ''')
        # --- V4 新增：好友请求表 ---
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS friend_requests (
                requester_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                status TEXT DEFAULT 'pending', -- pending, accepted, rejected
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (requester_id, receiver_id)
            )
        ''')
        # --- V4 新增：消息历史记录表 (服务器代码中有调用) ---
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_name TEXT NOT NULL,
                target TEXT NOT NULL,
                type TEXT NOT NULL, -- 'private' or 'group'
                content TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
        logger.info("V4 Database initialized successfully.")

    def _generate_unique_id(self, cursor, table, column, length) -> str:
        while True:
            range_start, range_end = 10 ** (length - 1), (10 ** length) - 1
            new_id = str(random.randint(range_start, range_end))
            cursor.execute(f"SELECT {column} FROM {table} WHERE {column} = ?", (new_id,))
            if cursor.fetchone() is None: return new_id

    # --- ！！！ V4 新增 ！！！ ---
    def get_user_by_id(self, user_id: str) -> Optional[tuple]:
        """根据 user_id 获取 (user_id, username)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT user_id, username FROM users WHERE user_id = ?', (user_id,))
        result = cursor.fetchone()
        conn.close()
        return result

    def get_user_by_username(self, username: str) -> Optional[tuple]:
        """根据用户名获取 (user_id, username, password_hash, salt)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT user_id, username, password_hash, salt FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        conn.close()
        return result

    def get_group_by_id(self, group_id: str) -> Optional[tuple]:
        """根据 group_id 获取 (group_id, name)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT group_id, name FROM groups WHERE group_id = ?', (group_id,))
        result = cursor.fetchone()
        conn.close()
        return result

    def add_user(self, username: str, password_hash: str, salt: str) -> Optional[str]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            user_id = self._generate_unique_id(cursor, "users", "user_id", 11)
            cursor.execute('INSERT INTO users (user_id, username, password_hash, salt) VALUES (?, ?, ?, ?)',
                           (user_id, username, password_hash, salt))
            conn.commit()
            logger.info(f"User '{username}' with ID '{user_id}' added.")
            return user_id
        except sqlite3.IntegrityError:
            logger.warning(f"Failed to add user '{username}'. May already exist.")
            return None
        finally:
            conn.close()

    def create_group(self, group_name: str, created_by_id: str) -> Optional[str]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            group_id = self._generate_unique_id(cursor, "groups", "group_id", 6)
            cursor.execute('INSERT INTO groups (group_id, name, created_by_id) VALUES (?, ?, ?)',
                           (group_id, group_name, created_by_id))
            cursor.execute('INSERT INTO group_members (group_id, user_id) VALUES (?, ?)',
                           (group_id, created_by_id))
            conn.commit()
            logger.info(f"Group '{group_name}' (ID: {group_id}) created by user ID {created_by_id}.")
            return group_id
        except sqlite3.IntegrityError:
            logger.warning(f"Failed to create group '{group_name}'.")
            return None
        finally:
            conn.close()

    def add_user_to_group(self, group_id: str, user_id: str) -> bool:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT id FROM groups WHERE group_id = ?', (group_id,))
            if not cursor.fetchone(): return False
            cursor.execute('INSERT INTO group_members (group_id, user_id) VALUES (?, ?)', (group_id, user_id))
            conn.commit()
            logger.info(f"User ID {user_id} added to group ID {group_id}.")
            return True
        except sqlite3.IntegrityError:
            return True  # Already in group is considered success
        finally:
            conn.close()

    def user_in_group(self, group_id: str, user_id: str) -> bool:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?', (group_id, user_id))
        result = cursor.fetchone() is not None
        conn.close()
        return result

    def get_user_groups(self, user_id: str) -> List[Tuple[str, str]]:
        """获取用户加入的所有群组，返回 (group_id, group_name) 元组列表"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT g.group_id, g.name
            FROM groups g
            JOIN group_members gm ON g.group_id = gm.group_id
            WHERE gm.user_id = ?
        ''', (user_id,))
        result = cursor.fetchall()
        conn.close()
        return result

    def get_history_messages(self, user1_id: str, user2_id: str, limit: int = 50) -> List[dict]:
        """获取两个用户之间的私聊历史记录（V2 - 健壮版）"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # --- 关键修复：在尝试获取名字前，先检查用户是否存在 ---
        user1_info = self.get_user_by_id(user1_id)
        user2_info = self.get_user_by_id(user2_id)

        if not user1_info or not user2_info:
            conn.close()
            return []  # 如果任一用户不存在，直接返回空列表

        user1_name = user1_info[1]
        user2_name = user2_info[1]
        # --- 修复结束 ---

        cursor.execute('''
              SELECT sender_name, content, timestamp
              FROM messages
              WHERE type = 'private' AND 
                    ((sender_name = ? AND target = ?) OR (sender_name = ? AND target = ?))
              ORDER BY timestamp DESC
              LIMIT ?
          ''', (user1_name, user2_id, user2_name, user1_id, limit))

        messages = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return messages[::-1]

    def get_group_history(self, group_id: str, limit: int = 50) -> List[dict]:
        """获取群聊历史记录"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
               SELECT sender_name, content, timestamp
               FROM messages
               WHERE type = 'group' AND target = ?
               ORDER BY timestamp DESC
               LIMIT ?
           ''', (group_id, limit))
        messages = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return messages[::-1]


    # --- ！！！ V4 新增：好友系统核心方法 ！！！ ---
    def get_friend_list(self, user_id: str) -> List[Tuple[str, str]]:
        """获取好友列表，返回 (friend_id, friend_username) 元组列表"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT f.friend_id, u.username
            FROM friends f
            JOIN users u ON f.friend_id = u.user_id
            WHERE f.user_id = ?
        ''', (user_id,))
        result = cursor.fetchall()
        conn.close()
        return result

    def are_friends(self, user1_id: str, user2_id: str) -> bool:
        """检查两人是否已是好友"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM friends WHERE user_id = ? AND friend_id = ?', (user1_id, user2_id))
        result = cursor.fetchone() is not None
        conn.close()
        return result

    def add_friend_request(self, requester_id: str, receiver_id: str) -> bool:
        """添加好友请求，如果已是好友或请求已存在则失败。如果对方已请求，则自动成为好友。"""
        if self.are_friends(requester_id, receiver_id):
            return False

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            # 检查反向请求是否存在
            cursor.execute('SELECT 1 FROM friend_requests WHERE requester_id = ? AND receiver_id = ?',
                           (receiver_id, requester_id))
            if cursor.fetchone():
                # <<< CHANGE: Pass the existing connection to prevent deadlock!
                return self.accept_friend_request(receiver_id, requester_id, existing_conn=conn)

            cursor.execute('INSERT OR IGNORE INTO friend_requests (requester_id, receiver_id) VALUES (?, ?)',
                           (requester_id, receiver_id))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # 请求已存在
        finally:
            conn.close()

    def accept_friend_request(self, requester_id: str, accepter_id: str, existing_conn=None) -> bool:
        """接受好友请求，建立双向好友关系。可以接收一个已存在的数据库连接以避免死锁。"""
        # <<< CHANGE START: Use existing connection if provided
        conn = existing_conn if existing_conn else sqlite3.connect(self.db_path)
        # <<< CHANGE END

        cursor = conn.cursor()
        try:
            # 验证请求是否存在
            cursor.execute("SELECT 1 FROM friend_requests WHERE requester_id = ? AND receiver_id = ? AND status = 'pending'", (requester_id, accepter_id))
            if not cursor.fetchone():
                # 如果是自动接受（对方也发了请求），那么原始请求可能不存在，这没关系
                pass

            # <<< CHANGE START: Use transaction on the passed-in connection
            if not existing_conn:
                cursor.execute('BEGIN TRANSACTION')
            # <<< CHANGE END

            # 建立双向好友关系
            cursor.execute('INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?, ?)', (requester_id, accepter_id))
            cursor.execute('INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?, ?)', (accepter_id, requester_id))
            # 删除好友请求
            cursor.execute('DELETE FROM friend_requests WHERE requester_id = ? AND receiver_id = ?', (requester_id, accepter_id))
            # 也删除可能存在的反向请求
            cursor.execute('DELETE FROM friend_requests WHERE requester_id = ? AND receiver_id = ?', (accepter_id, requester_id))

            # <<< CHANGE START: Only commit/close if this function created the connection
            if not existing_conn:
                conn.commit()
            return True
        except Exception as e:
            if not existing_conn:
                conn.rollback()
            logger.error(f"Failed to accept friend request: {e}")
            return False
        finally:
            if not existing_conn:
                conn.close()
            # <<< CHANGE END

    def save_message(self, sender_name, target, msg_type, content, gn=None):
        """保存消息记录 (服务器代码中已调用)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute(
                'INSERT INTO messages (sender_name, target, type, content) VALUES (?, ?, ?, ?)',
                (sender_name, target, msg_type, content)
            )
            conn.commit()
        except Exception as e:
            logger.error(f"Failed to save message: {e}")
        finally:
            conn.close()
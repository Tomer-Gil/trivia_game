import re


# Protocol Constants

# Fields
CMD_FIELD_LENGTH = 16   # Exact length of cmd field (in bytes)
LENGTH_FIELD_LENGTH = 4   # Exact length of length field (in bytes)
MAX_DATA_LENGTH = 10 ** LENGTH_FIELD_LENGTH - 1  # Max size of data field according to protocol

# Total message
MSG_HEADER_LENGTH = CMD_FIELD_LENGTH + 1 + LENGTH_FIELD_LENGTH + 1  # Exact size of header (CMD+LENGTH fields)
MAX_MSG_LENGTH = MSG_HEADER_LENGTH + MAX_DATA_LENGTH  # Max size of total message

# Delimiters
DELIMITER = "|"  # Delimiter character in protocol
DATA_DELIMITER = "#"  # Delimiter in the data part of the message
LOGGED_USERS_DELIMITER = ","

# Protocol Messages 
# In this dictionary we will have all the client and server command names

PROTOCOL_CLIENT = {
	"login_msg": "LOGIN",
	"logout_msg": "LOGOUT",
	"get_logged_users": "LOGGED",
	"get_my_score_request": "MY_SCORE",
	"get_high_scores_list": "HIGHSCORE",
	"get_question": "GET_QUESTION",
	"send_answer_to_server": "SEND_ANSWER",
	"exit": "QUIT",
}  # .. Add more commands if needed


PROTOCOL_SERVER = {
	"login_ok_msg": "LOGIN_OK",
	"login_failed_msg": "ERROR",
	"logged_users_response": "LOGGED_ANSWER",
	"user_score_msg": "YOUR_SCORE",
	"high_scores_list": "ALL_SCORE",
	"question_for_user": "YOUR_QUESTION",
	"no_more_questions_msg": "NO_QUESTIONS",
	"correct_answer_msg": "CORRECT_ANSWER",
	"wrong_answer_msg": "WRONG_ANSWER",
}  # ..  Add more commands if needed


MENU_OPTIONS = {
	"View Logged Users": "get_logged_users",
	"View my score": "get_my_score_request",
	"View high score table": "get_high_scores_list",
	"Play a question!": "get_question",
	"Exit": "exit",
}


# Other constants

ERROR_RETURN = None  # What is returned in case of an error


def build_message(cmd, data):
	"""
	Gets command name (str) and data field (str) and creates a valid protocol message
	Returns: str, or None if error occurred
	"""
	if cmd not in PROTOCOL_CLIENT.values() and cmd not in PROTOCOL_SERVER.values():
		return ERROR_RETURN
	data = str(data)
	if len(data) > MAX_DATA_LENGTH:
		return ERROR_RETURN, ERROR_RETURN
	# For test file - data length is padded with 0's rather than spaces.
	full_msg = cmd.ljust(CMD_FIELD_LENGTH) + DELIMITER + str(len(data)).zfill(LENGTH_FIELD_LENGTH) + DELIMITER + data
	# full_msg = cmd.ljust(CMD_FIELD_LENGTH) + DELIMITER + str(len(data)).rjust(LENGTH_FIELD_LENGTH) + DELIMITER + (data)

	return full_msg


def parse_message(msg):
	"""
	Parses protocol message and returns command name and data field
	Returns: cmd (str), data (str). If some error occurred, returns None, None
	"""
	if type(msg) is not str:
		return ERROR_RETURN, ERROR_RETURN
	pattern = re.compile(r"^[A-Z]+_*[A-Z]+\s*\|\s*\d{0,4}\|[\s\S]*$")
	match = pattern.search(msg)
	if match is None:
		return ERROR_RETURN, ERROR_RETURN
	cmd, data_len, data = match.group().split(DELIMITER, 2)

	# The following condition was written because this regex pattern is not powerful enough to limit the length of a field
	# in the string.
	# Therefore, I needed to determine that none of the fields are longer nor shorter than
	# what the protocol permits.
	# It is recommended to delete it if I ever find a powerful enough regex pattern to do it.

	# Validates the fields length
	if len(cmd) != CMD_FIELD_LENGTH or len(data_len) != LENGTH_FIELD_LENGTH or len(data) >= MAX_MSG_LENGTH:
		return ERROR_RETURN, ERROR_RETURN

	cmd = cmd.strip()
	# data_len can be represented as a number preceded by spaces or by zero's.
	# If it is preceded by zeros, .strip won't have any effect.
	# If it is preceded by spaces, it will remove them.
	data_len = int(data_len.strip())

	# Validates the command is legal
	if cmd not in PROTOCOL_CLIENT.values() and cmd not in PROTOCOL_SERVER.values():
		return ERROR_RETURN, ERROR_RETURN

	# Validates that the length of the message according to the message length field is indeed it's length.
	if data_len != len(data):
		return ERROR_RETURN, ERROR_RETURN

	return cmd, data

	
def split_data(data):
	"""
	Helper method. gets a string, representing the data field in the message. Splits the string
	using protocol's data field delimiter (#).
	Returns: list of fields if all ok.
	"""
	return data.split(DATA_DELIMITER)


def join_data(msg_fields):
	"""
	Helper method. Gets a list, joins all of it's fields to one string divided by the data delimiter. 
	Returns: string that looks like cell1#cell2#cell3
	"""
	return DATA_DELIMITER.join([str(c) for c in msg_fields])


# print(build_message("LOGIN", "user#pass"))
# print(parse_message(b"LOGIN          |    8|user#pass"))

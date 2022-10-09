##############################################################################
# server.py
##############################################################################

import socket
import select
import sys
sys.path.append(r"..\u1")
import chatlib
import random
import requests  # to get questions from outer server
import json  # to parse the returned questions
import html  # to unescape the returned question


class OutOfQuestionsError(Exception):

	def __str__(self):
		return "Good for you, you've answered all the questions in the database!"


# GLOBALS

ERROR_MSG = "Error! "
SERVER_PORT = 5678
SERVER_IP = "127.0.0.1"

MAX_MSG_LENGTH = 1024

ADD_POINTS = 5

AMOUNT_OF_QUESTIONS = 5  # Maximum possible is 50

# It's more convenient to write this variable as a global variable, that is, out of the build message function.
# That way, I won't have to pass it each time I want to send a message.
MESSAGES_TO_SEND = []  # list of tuples - tuple of IP and port, and message.

# SOCKET CREATOR


def setup_socket():
	"""
	Creates new listening socket and returns it
	Receives: -
	Returns: the socket object
	"""
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.bind((SERVER_IP, SERVER_PORT))
	sock.listen()

	return sock


#########################
# HELPER SOCKET METHODS
#########################

def build_and_send_message(conn, code, data):
	"""
	Helper function.
	Builds a new message using chatlib, wanted code and message.
	Prints debug info, then sends it to the given socket.
	Parameters: conn (socket object), code (str), data (str)
	Returns: Nothing
	"""
	# I have to use the global keyword here becuase I WRITE to the global variable (by default) MESSAGES_TO_SEND.
	# Had I only read it, I hadn't need to specifically use the keyword "global"
	global MESSAGES_TO_SEND
	full_msg = chatlib.build_message(code, data)
	# conn.send(full_msg.encode())
	# print(MESSAGES_TO_SEND)
	# Pay attention.
	# MESSAGES_TO_SEND functions as a leaving mail box.
	# At the end of the main function, I iterate over it, and compare each socket to the ready_to_write list
	# return from the select mthod.
	# The select method return socket OBJECTS.
	# Therefore, there's no need to insert conn.getpeername() to MESSAGES_TO_SEND - those are two different objects.
	MESSAGES_TO_SEND += [(conn, full_msg)]


def parse_message(message):
	"""
	Helper function.
	Parses a message using chatlib.
	Parameters: conn (socket object)
	Returns: cmd (str) and data (list) of the received message.
	If error occurred, will return None, None
	"""
	cmd, data = chatlib.parse_message(message)
	data = chatlib.split_data(data)  # parsing the data field

	return cmd, data


def send_error(conn, error_msg):
	"""
	Send error message with given message
	Receives: socket, message error string from called function
	Returns: None
	"""
	build_and_send_message(conn, chatlib.PROTOCOL_SERVER["login_failed_msg"], error_msg)


def print_clients_sockets():
	for client in logged_users:
		print("\t{}: {}".format(client, logged_users[client]))


def create_random_question(client_socket):
	# Consider use generators when the db will be very large, so python won't have to load it all at once and consume
	# all the memory.
	print("create_random_question says user questions are: {}\nRemember remove after debugging.".format(
		", ".join([str(asked) for asked in users[logged_users[client_socket.getpeername()]]["questions_asked"]])
	))
	asked_questions_list = users[logged_users[client_socket.getpeername()]]["questions_asked"]
	if len(asked_questions_list) == AMOUNT_OF_QUESTIONS:
		raise OutOfQuestionsError
	while True:
		random_question = random.choice(list(questions.keys()))
		if random_question not in asked_questions_list:
			break
	users[logged_users[client_socket.getpeername()]]["questions_asked"] += [random_question]
	return "{}{}{}{}{}".format(
		random_question,
		chatlib.DATA_DELIMITER,
		questions[random_question]["question"],
		chatlib.DATA_DELIMITER,
		chatlib.DATA_DELIMITER.join(questions[random_question]["answers"]),
	)


################
# Data Loaders
################


def load_user_database(is_online=False, is_first_copy_to_db=False):
	"""
	Loads users list from file	## FILE SUPPORT TO BE ADDED LATER
	Receives: -
	Returns: user dictionary
	"""
	if is_first_copy_to_db:
		# Helper section I've made in order to copy the users to the db.
		users = {
			"yossi": {
				"password": "123",
				"score": 50,
				"questions_asked": [],
			},
			"test": {
				"password": "test",
				"score": 0,
				"questions_asked": [],
			},
			"master": {
				"password": "master",
				"score": 200,
				"questions_asked": [],
			},
		}
		with open("users.txt", "w") as users_db:
			json.dump(users, users_db)
	else:
		# Currently doesn't support encryption and decryption
		with open("users.txt", "r") as users_db:
			users = json.load(users_db)
		print("Loaded users database.")
		if is_online:
			for user in users.keys():
				token_response = json.loads(requests.get("https://opentdb.com/api_token.php?command=request").text)
				if token_response["response_code"] == 0:
					print(token_response["response_message"])
					token = token_response["token"]
					users[user]["token"] = token
				else:
					# Add support for moving to offline mode later.
					print("Some sort of a problem while trying to get token from the server.")
	return users


def update_users_db():
	with open("users.txt", "w") as users_db:
		json.dump(users, users_db)
	print("Users database has been updated successfully.")


def load_questions(from_web=True, is_first_copy_to_db=False):
	"""
	Loads questions bank from file	## FILE SUPPORT TO BE ADDED LATER
	Receives: -
	Returns: questions dictionary
	"""
	questions = {}  # Default value to be returned
	if from_web:
		token_response = json.loads(requests.get("https://opentdb.com/api_token.php?command=request").text)
		if token_response["response_code"] == 0:
			print(token_response["response_message"])
			token = token_response["token"]
		else:
			# Add support for moving to offline mode later.
			print("Some sort of a problem while trying to get token from the server.")
		response = requests.get(
			"https://opentdb.com/api.php?amount={}&type=multiple&token={}".format(AMOUNT_OF_QUESTIONS, token)
		)
		# json.loads does not treat the string as a raw string, that is, if it encounters a " sign, it thinks it symbols
		# a beginning of key or value (and expects : or , respectively).
		questions_obj = json.loads(response.text)
		response_code = questions_obj["response_code"]
		if response_code == 0:
			questions_list = questions_obj["results"]
			for i, question in enumerate(questions_list):
				concatenated_answers = question["incorrect_answers"] + [question["correct_answer"]]
				random.shuffle(concatenated_answers)
				questions[i] = {
					"question": html.unescape(question["question"]),
					"answers": [html.unescape(answer) for answer in concatenated_answers],
					"correct": concatenated_answers.index(question["correct_answer"]) + 1,
				}  # add a comma in the end makes it a tuple consisted of one dictionary
		elif response_code == 1:
			print(
				"No Results: Could not return results. The API doesn't have enough questions for your query." +
				"(Ex. Asking for 50 Questions in a Category that only has 20.)"
			)
		elif response_code == 2:
			print("Invalid Parameter: Contains an invalid parameter. Arguements passed in aren't valid. (Ex. Amount = Five)")
		elif response_code == 3:
			print("Token Not Found: Session Token does not exist.")
		elif response_code == 4:
			print("Token Empty: Session Token has returned all possible questions for the specified query. Resetting \
			the Token is necessary.")
	else:
		if is_first_copy_to_db:
			questions = {
				2313: {
					"question": "How much is 2+2",
					"answers": ["3", "4", "2", "1"],
					"correct": 2,
				},
				4122: {
					"question": "What is the capital of France?",
					"answers": ["Lion", "Marseille", "Paris", "Montpellier"],
					"correct": 3,
				},
			}
			# json.dumps serialize the keys as string, even if they are of int type.
			with open("questions.txt", "w") as questions_db:
				json.dump(questions, questions_db)
		else:
			print("hey q")
			# Currently doesn't support encryption and decryption
			with open("questions.txt", "r") as questions_db:
				temp_questions = json.load(questions_db)
			# The questions' id's saves as strings in the database, but I use them as integers later
			# (corresponding to the questions from the outer server).
			questions = {}
			for question_id, headers in temp_questions.items():
				questions[int(question_id)] = headers
	return questions


#####################
# DATABASE GLOBALS
#####################

users = load_user_database()
questions = load_questions()
logged_users = {}  # a dictionary of client hostnames (keys) to usernames (values).


###################
# MESSAGE HANDLING
###################


def handle_answer_message(conn, data):
	question, answer = [int(i) for i in data]
	if question not in questions.keys():
		print("Sorry, it seems like I can't find this question number.")
	elif answer not in range(1, 5):
		print("Sorry, can only understand 1-4 answer.")
	elif questions[int(question)]["correct"] == int(answer):
		users[logged_users[conn.getpeername()]]["score"] += ADD_POINTS
		build_and_send_message(conn, chatlib.PROTOCOL_SERVER["correct_answer_msg"], "")
	else:
		build_and_send_message(conn, chatlib.PROTOCOL_SERVER["wrong_answer_msg"], questions[int(question)]["correct"])


def handle_question_message(conn):
	try:
		question = create_random_question(conn)
	except OutOfQuestionsError:
		build_and_send_message(
			conn,
			chatlib.PROTOCOL_SERVER["no_more_questions_msg"],
			"You can exit the game and re-enter in order to renew the questions stock (same questions will be used)."
		)
	except IndexError:  # random.choice in create_random_question returns this if the iterable is empty
		# Change chatlib protocol to support more error rather than failed logging in.
		build_and_send_message(conn, chatlib.PROTOCOL_SERVER["login_failed_msg"], "Sorry, the questions database is empty.")
	# Consider remove this condition.
	# Don't see a reason question will be returned as None (or empty dictionary)
	# if question is None:  # PEP 8: E711 comparison to None should be 'if cond is None:' (instead of ==)
		# print("handle_question_message got None type question from create_random_question.")
	else:
		build_and_send_message(conn, chatlib.PROTOCOL_SERVER["question_for_user"], question)


def handle_logged_message(conn):
	build_and_send_message(
		conn,
		chatlib.PROTOCOL_SERVER["logged_users_response"],
		",".join([username for username in logged_users.values()])
	)


def handle_highscore_message(conn):
	sorted_indices = (sorted(users, key=lambda user: users[user]["score"], reverse=True))
	build_and_send_message(
		conn,
		chatlib.PROTOCOL_SERVER["high_scores_list"],
		"\n".join(["\t{}: {}".format(user, users[user]["score"]) for user in sorted_indices])
	)


def handle_getscore_message(conn):
	# global users
	username = logged_users[conn.getpeername()]
	score = str(users[username]["score"])
	build_and_send_message(conn, chatlib.PROTOCOL_SERVER["user_score_msg"], score)


def handle_logout_message(conn, client_sockets):
	"""
	Closes the given socket (in later chapters, also remove user from logged_users dictionary)
	Receives: socket
	Returns: None
	"""
	# global logged_users
	print("Updating users db.", end="\n" * 2)
	users[logged_users[conn.getpeername()]]["questions_asked"] = []
	update_users_db()
	print("Closing client's socket.")
	client_sockets.remove(conn)
	# User can be connected, that is, share a socket with the server, but not logged in, because I stated that logged in
	# means his credentials had been validated.
	if conn.getpeername() in logged_users:
		del logged_users[conn.getpeername()]
	conn.close()
	# print_client_sockets(client_sockets)


def handle_login_message(conn, data):  # Validates logged user credentials
	"""
	Gets socket and message data of login message. Checks  user and pass exists and match.
	If not - sends error and finished. If all ok, sends OK message and adds user and address to logged_users
	Receives: socket, message code and data
	Returns: None (sends answer to client)
	"""
	# global users  # This is needed to access the same users dictionary from all functions
	# global logged_users	 # To be used later
	username, password = data

	if username not in users.keys():
		build_and_send_message(conn, chatlib.PROTOCOL_SERVER["login_failed_msg"], "Error! Username does not exists.")
		return  # Look for a more "pythonic" way to write it
	if password != users[username]["password"]:
		build_and_send_message(conn, chatlib.PROTOCOL_SERVER["login_failed_msg"], "Error! Password does not match!")
		return  # Look for a more "pythonic" way to write it
	logged_users[conn.getpeername()] = username
	build_and_send_message(conn, chatlib.PROTOCOL_SERVER["login_ok_msg"], "")


def handle_client_message(conn, cmd, data):
	"""
	Gets message code and data and calls the right function to handle command.
	Logout message is handeled with other logic - outside this function.
	Receives: socket, message code and data
	Returns: None
	"""
	# global logged_users  # To be used later
	# I don't want to disclose information about the permitted actions, so I make sure the user is logged in before
	# I validate his message
	if conn.getpeername() not in logged_users:
		if cmd != chatlib.PROTOCOL_CLIENT["login_msg"]:
			# add "invalid request - user not connected" error later
			pass
		else:
			handle_login_message(conn, data)
	else:
		if cmd not in chatlib.PROTOCOL_CLIENT.values():
			send_error(conn, "Sorry, I couldn't understand that. Please try again.")
		elif cmd == chatlib.PROTOCOL_CLIENT["get_my_score_request"]:
			handle_getscore_message(conn)
		elif cmd == chatlib.PROTOCOL_CLIENT["get_high_scores_list"]:
			handle_highscore_message(conn)
		elif cmd == chatlib.PROTOCOL_CLIENT["get_logged_users"]:
			handle_logged_message(conn)
		elif cmd == chatlib.PROTOCOL_CLIENT["get_question"]:
			handle_question_message(conn)
		elif cmd == chatlib.PROTOCOL_CLIENT["send_answer_to_server"]:
			handle_answer_message(conn, data)


def main():
	# Initializes global users and questions dictionaries using load functions, will be used later
	# global users
	# global questions

	print("Welcome to Trivia Server!", end="\n" * 2)
	print("Setting up server on port {}...".format(SERVER_PORT))
	server_socket = setup_socket()
	print("Server is up and listening, waiting for a connection...", end="\n" * 2)

	client_sockets = []
	while True:
		# print("Server says: before select")
		ready_to_read, ready_to_write, in_error = select.select([server_socket] + client_sockets, client_sockets, [])
		# print("Server says: after select")
		for current_socket in ready_to_read:
			if current_socket is server_socket:  # detecting new client connected
				client_socket, client_address = current_socket.accept()
				print("New client joined!", client_address, end="\n" * 2)
				client_sockets.append(client_socket)
			else:  # existing client socket
				try:
					received_message = current_socket.recv(MAX_MSG_LENGTH).decode()
				# .select() had been triggered because of a sudden disconnection from the user,
				# probably due to a sudden close of the window by him
				except ConnectionResetError:
					# One user can make the server stop, no matter how many users are connected and if the user who
					# closed the window is the first client or not.
					print("Caught ConnectionResetError (user manually closed the window).\n{} left the server.".format(
						current_socket.getpeername()
					))
					handle_logout_message(current_socket, client_sockets)
				else:
					if received_message == "":
						print("User used ctrl + c.\n{} left the server.".format(current_socket.getpeername()))
						handle_logout_message(current_socket, client_sockets)
					else:
						cmd, data = parse_message(received_message)
						print("[CLIENT] " + str(current_socket.getpeername()) + " msg: " + received_message)  # Debug print
						if cmd == chatlib.PROTOCOL_CLIENT["logout_msg"]:
							print("Client log out.")
							handle_logout_message(current_socket, client_sockets)
						else:
							handle_client_message(current_socket, cmd, data)
		for message in MESSAGES_TO_SEND:
			current_socket, reply_message = message
			if current_socket in ready_to_write:
				current_socket.send(reply_message.encode())
				print("[SERVER] {} msg: {}".format(current_socket.getpeername(), repr(reply_message)), end="\n" * 2)  # Debug print
				# print("[SERVER] " + str(current_socket.getpeername()) + " msg: " + repr(reply_message))  # Debug print
				MESSAGES_TO_SEND.remove(message)
		# I can print something here, but as long as one user is connected, he will remain in the write_list argument to
		# select method, which will keep on releasing the program and let it keep running.
		# So, this print has well will keep on printing, until select will block the program from running - when
		# it will get no socket in none of it's parameters.


if __name__ == '__main__':
	main()

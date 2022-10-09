import socket
import sys
sys.path.append(r"..\u1")
import chatlib  # To use chatlib functions or consts, use chatlib.****


class InvalidUserCommandError(Exception):

    def __str__(self):
        return "Sorry, I couldn't find this command. Please try again."


class UnsupportedOperationError(Exception):

    def __str__(self):
        return "Sorry, this operation is not currently supported."


class InvalidUserAnswerError(Exception):

    def __str__(self):
        return "Sorry, I couldn't understand that. Please try again."


SERVER_IP = "127.0.0.1"  # Our server will run on same computer as client
SERVER_PORT = 5678

IS_EXIT_USER_AFTER_NO_MORE_QUESTIONS = False
NO_MORE_QUESTIONS_MESSAGE = "Wow! You've managed to answer all the questions! That Awesome! " +\
                            "That was fun! Hope you've enjoyed! Hope to see you next time."

# HELPER SOCKET METHODS


def build_and_send_message(conn, code, data):
    """
    Helper function.
    Builds a new message using chatlib, wanted code and message.
    Prints debug info, then sends it to the given socket.
    Parameters: conn (socket object), code (str), data (str)
    Returns: Nothing
    """
    full_msg = chatlib.build_message(code, data)
    conn.send(full_msg.encode())
    # print("Message sent to the server:", full_msg)  - debug


def recv_message_and_parse(conn):
    """
    Helper function.
    Receives a new message from given socket,
    then parses the message using chatlib.
    Parameters: conn (socket object)
    Returns: cmd (str) and data (str) of the received message.
    If error occurred, will return None, None
    """
    full_msg = conn.recv(1024).decode()
    # For case the server sends messages which have specials chars in it without escaping them.
    # print("Message received from the server:", repr(full_msg))  - debug
    cmd, data = chatlib.parse_message(full_msg)  # data is currently non-parsed.
    data = chatlib.split_data(data)  # parsing the data field
    # print("Received cmd=%s\nReceived data=%s" % (cmd, repr(data)))  - debug
    return cmd, data


def build_send_recv_parse(conn, cmd, data):
    """Helper function.
    "Concatenates" the build_and_send_message and resv_and_parse functions.
    """
    build_and_send_message(conn, cmd, data)
    return recv_message_and_parse(conn)


def connect():
    user_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    user_socket.connect((SERVER_IP, SERVER_PORT))
    return user_socket


def login(conn):
    received_command = ""
    while received_command != chatlib.PROTOCOL_SERVER["login_ok_msg"]:
        username = input("Please enter username: \n")
        password = input("Please enter password: \n")
        received_command, data = build_send_recv_parse(
            conn,
            chatlib.PROTOCOL_CLIENT["login_msg"],
            username + chatlib.DATA_DELIMITER + password
        )
        if received_command != chatlib.PROTOCOL_SERVER["login_ok_msg"]:
            print("Couldn't login.")
    print("Logged in!", end="\n" * 2)


def logout(conn):
    build_and_send_message(conn, chatlib.PROTOCOL_CLIENT["logout_msg"], "")


def get_score(conn):
    cmd, data = build_send_recv_parse(conn, chatlib.PROTOCOL_CLIENT["get_my_score_request"], "")
    if cmd != chatlib.PROTOCOL_SERVER["user_score_msg"]:
        print("Got unexpected msg_code")
    else:
        return int(data[0])


def get_high_score(conn):
    # According to the course server, the received data is a list of one item.
    # Therefore, I referred to it as data[0].
    # I think about changing the server to return each player in a different cell.
    cmd, data = build_send_recv_parse(conn, chatlib.PROTOCOL_CLIENT["get_high_scores_list"], "")
    if cmd != chatlib.PROTOCOL_SERVER["high_scores_list"]:
        error_and_exit("Got unexpected msg_code")
    else:
        return "\n".join(data[0].split("\n"))


def play_question(conn):
    cmd, data = build_send_recv_parse(conn, chatlib.PROTOCOL_CLIENT["get_question"], "")
    # NOTE
    # I currently haven't implemented yet the function that parses the fields out the msg field.
    # This piece of code to be replaced.
    # Currently question_id is set to "4122" (some arbitrary and existing question) for compatibility reason.
    # The server might not  return any question / return always the same question, but the program will run.
    # Put under comment - 09/01/2021
    # question_id = "4122"
    if cmd not in (chatlib.PROTOCOL_SERVER["question_for_user"], chatlib.PROTOCOL_SERVER["no_more_questions_msg"]):
        error_and_exit("Got unexpected msg_code")
    elif cmd == chatlib.PROTOCOL_SERVER["no_more_questions_msg"]:
        if IS_EXIT_USER_AFTER_NO_MORE_QUESTIONS:
            error_and_exit("No more questions left! That was fun! Hope to see you soon!")
        print("No more questions left! That was fun! Hope to see you soon!")
    else:
        question_id, question, answers = data[0], \
                                         data[1], \
                                         ["\t" + str(i) + ". " + answer for i, answer in enumerate(data[2:], 1)]
        print(question + "\n" + "\n".join(answers), end="\n" * 2)
        while True:
            try:
                user_answer = int(input("Please enter your answer: "))
                if user_answer not in range(1, 5):
                    raise InvalidUserAnswerError

                # Expected values - Correct/Wrong response + the correct answer id the answer was incorrect
                cmd, data = build_send_recv_parse(
                    conn,
                    chatlib.PROTOCOL_CLIENT["send_answer_to_server"],
                    question_id + chatlib.DATA_DELIMITER + str(user_answer)
                )
                if cmd not in (chatlib.PROTOCOL_SERVER["correct_answer_msg"], chatlib.PROTOCOL_SERVER["wrong_answer_msg"]):
                    error_and_exit(
                        "Sorry, something went wrong while trying to get response for the question from the server."
                    )
                if cmd == chatlib.PROTOCOL_SERVER["wrong_answer_msg"]:
                    print("Sorry, that was wrong. The answer is", data[0])
                else:
                    print("Well done! You were right!")
            except ValueError:
                print("here")
            except InvalidUserAnswerError as e:
                print(e)
            else:
                break


def get_logged_users(conn):
    cmd, data = build_send_recv_parse(conn, chatlib.PROTOCOL_CLIENT["get_logged_users"], "")
    if cmd != chatlib.PROTOCOL_SERVER["logged_users_response"]:
        error_and_exit("Sorry, something went wrong while trying to get the logged in users list from the server.")
    print("\n".join(data[0].split(chatlib.LOGGED_USERS_DELIMITER)))


def error_and_exit(error_msg):
    exit(error_msg)


def main():
    user_socket = connect()
    login(user_socket)
    print("Hey user! Here are you option:\n" + "\n".join(
        ["{}. {}".format(str(i), cmd) for i, cmd in enumerate(chatlib.MENU_OPTIONS)]
    ))
    # The connecting node is the first pair in each dictionary, that is, in index 0.
    menu_protocol_options = list(chatlib.MENU_OPTIONS.values())
    while True:
        try:
            print()
            cmd_num = int(input("Please enter the code for what you'd like to do: "))
            if cmd_num not in range(len(menu_protocol_options)):
                raise InvalidUserCommandError
            # Last item in the client's option dictionary should be exit
            elif cmd_num == len(menu_protocol_options) - 1:
                break
            if menu_protocol_options[cmd_num] == "get_my_score_request":  # Get my score
                print(get_score(user_socket))
            elif menu_protocol_options[cmd_num] == "get_high_scores_list":  # Get high-scores list
                print(get_high_score(user_socket))
            elif menu_protocol_options[cmd_num] == "get_question":
                play_question(user_socket)
            elif menu_protocol_options[cmd_num] == "get_logged_users":
                get_logged_users(user_socket)
        except ValueError:
            print("Sorry, I couldn't understand that. Please try again.")
        except InvalidUserCommandError as e:
            print(e)
        except UnsupportedOperationError as e:
            print(e)
    logout(user_socket)
    print("Closing client socket")
    user_socket.close()


if __name__ == '__main__':
    main()

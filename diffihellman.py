from random import randint
from sympy import isprime
from sympy.ntheory.residue_ntheory import primitive_root
from sympy.ntheory.generate import randprime
from simplecrypt import encrypt, decrypt
import argparse

visible = False

def create_numbers():
	while True:
		P = randprime(10**59, 10**60)
		if (((P - 1) % 2 == 0) and isprime((P - 1) // 2)):
			break
	G = primitive_root(P)
	return P, G

class Agent:

	def __init__(self, name, p, g):
		self.name = name
		self.P = p
		self.G = g
		self.__key = None

	def generate_private_number(self):
		global visible
		self.__key = randint(10**59, 10**60)
		if visible:
			print(f"{self.name} private number:\033[32m\t{self.__key}\033[0m")

	def get_reminder(self):
		return pow(self.G, self.__key, self.P)

	def encrypt(self, message, reminder):
		secret_key = pow(reminder, self.__key, self.P)
		if visible:
			print(f"{self.name} secret key:\033[32m\t\t{secret_key}\033[0m")
		return encrypt(str(secret_key), message)

	def decrypt(self, cipher, reminder):
		secret_key = pow(reminder, self.__key, self.P)
		if visible:
			print(f"{self.name} secret key:\033[32m\t\t{secret_key}\033[0m")
		return decrypt(str(secret_key), cipher).decode()


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Diffi Hellman protocol simulation.")

	mutexgr = parser.add_mutually_exclusive_group(required=True)
	mutexgr.add_argument(
		"-m", "--message",
		help="The text for encryption.",
		type=str
		)

	parser.add_argument(
		"-v", "--visible",
        action='store_true',
		help="Make all numbers and secret keys visible."
        )

	args = parser.parse_args()

	visible = args.visible

	message = args.message

	P, G = create_numbers()

	Agent_1 = Agent("1", P, G)
	Agent_2 = Agent("2", P, G)

	Agent_1.generate_private_number()
	Agent_2.generate_private_number()

	Agent_2_reminder = Agent_2.get_reminder()
	Agent_1_reminder = Agent_1.get_reminder()

	if visible:
		print(f"1 open key B:\033[32m\t\t{Agent_1_reminder}\033[0m")
		print(f"2 open key A:\033[32m\t\t{Agent_2_reminder}\033[0m")

	encrypted = Agent_2.encrypt(message, Agent_1_reminder)
	decrypted = Agent_1.decrypt(encrypted, Agent_2_reminder)
	print("\n======\033[32mDiffi Hellman protocol\033[0m======")
	print(f"Message: \n\033[32m\t{message}\033[0m")
	print(f"Encrypted message: \n\033[32m\t{encrypted.hex()}\033[0m")
	print(f"Decrypted message: \n\033[32m\t{decrypted}\033[0m")

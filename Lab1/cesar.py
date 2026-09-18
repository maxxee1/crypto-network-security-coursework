## llamar desde termiinal python3 cesar.py 'texto' numero_de_rotacion
import argparse


def cifrar_cesar(texto, corrimiento):
	resultado = []

	for caracter in texto:
		if "A" <= caracter <= "Z":
			base = ord("A")
			caracter_cifrado = chr((ord(caracter) - base + corrimiento) % 26 + base)
		elif "a" <= caracter <= "z":
			base = ord("a")
			caracter_cifrado = chr((ord(caracter) - base + corrimiento) % 26 + base)
		else:
			caracter_cifrado = caracter

		resultado.append(caracter_cifrado)
	return "".join(resultado)


def main():
	parser = argparse.ArgumentParser(description="Cifra texto utilizando el algoritmo César.")
	parser.add_argument("texto", nargs="?", help="Texto que se desea cifrar")
	parser.add_argument("corrimiento", nargs="?", type=int, help="Corrimiento de las letras")
	argumentos = parser.parse_args()

	if argumentos.texto is None or argumentos.corrimiento is None:
		texto = input("Ingrese el texto a cifrar: ")
		corrimiento = int(input("Ingrese el corrimiento: "))
	else:
		texto = argumentos.texto
		corrimiento = argumentos.corrimiento

	print("Texto cifrado:", cifrar_cesar(texto, corrimiento))


if __name__ == "__main__":
	main()

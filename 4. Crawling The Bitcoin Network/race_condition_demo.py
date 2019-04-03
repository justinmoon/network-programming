import threading

x = 0

def add():
    global x
    for i in range(1000000):
        x = x + 1

def sub():
    global x
    for i in range(1000000):
        x = x - 1

def main():
    # run the adder
    adder = threading.Thread(target=add)
    adder.start()

    # run the subtracter
    subtracter = threading.Thread(target=sub)
    subtracter.start()

    # wait for both to finish
    adder.join()
    subtracter.join()

    # Should be 0, right?
    print(x)


main()


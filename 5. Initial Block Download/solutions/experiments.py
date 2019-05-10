from op import *
from script import *
from io import BytesIO


def genesis_script_sig():
    raw = bytes.fromhex('4d04ffff001d0104455468652054696d6573203033\
    2f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64\
    206261696c6f757420666f722062616e6b73')
    stream = BytesIO(raw)
    s = Script.parse(stream)
    print(s.evaluate(1))  # True

def foo_script():
    script = Script([b'foo'])
    print(script.evaluate(1))  # True

def false_script():
    script = Script([b''])
    print(script.evaluate(1))

    script = Script([0])
    print(script.evaluate(1))

    script = Script([-1])
    print(script.evaluate(1))

false_script()

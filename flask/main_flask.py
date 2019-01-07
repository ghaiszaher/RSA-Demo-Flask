#!/usr/bin/env python3

from flask import Flask, render_template, request
import sys

sys.path.append('../library')
import RSALibrary
from TimeLibrary import timed_function_beautified

app = Flask(__name__)

n, e, d, p, q = 0, 0, 0, 0, 0
bits = 512
min_e = 3


@app.route('/')
def index():
    global n, e, d, min_e, bits
    context = {
        'n': n,
        'e': e,
        'd': d,
        'min_e': min_e,
        'bits': bits
    }
    return render_template('index.html', **context)


@app.route('/genkeys_pre')
def generate_keys_pre():
    global n, e, d, min_e, bits, p, q
    min_e_param = request.args.get('min_e', '').strip()
    bits_param = request.args.get('bits', '').strip()
    if min_e_param:
        min_e = int(min_e_param)
    if bits_param:
        bits = int(bits_param)
    # (n, e, d), time_needed = timed_function_beautified(RSALibrary.generate_keys, bits, min_e)
    context = {
        'n': n,
        'e': e,
        'd': d,
        'p': p,
        'q': q,
        'min_e': min_e,
        'bits': bits
    }
    return render_template('generate_keys.html', **context)


@app.route('/genkeys')
def generate_keys():
    global n, e, d, min_e, bits, p, q
    min_e_param = request.args.get('min_e', '').strip()
    bits_param = request.args.get('bits', '').strip()
    if min_e_param:
        min_e = int(min_e_param)
    if bits_param:
        bits = int(bits_param)
    if bits > 2048:
        raise Exception("Max bits is 2048")
    (n, e, d, p, q), time_needed = timed_function_beautified(RSALibrary.generate_keys, bits, min_e, True)
    context = {
        'n': n,
        'e': e,
        'd': d,
        'p': p,
        'q': q,
        'min_e': min_e,
        'time_needed': time_needed,
        'bits': bits
    }
    return render_template('generate_keys.html', **context)


@app.route('/enterkeys', methods=['GET', 'POST'])
def enter_keys():
    global n, e, d, min_e, bits, p, q
    saved = False
    if request.method == 'POST':
        n = int(request.form.get('n'))
        e = int(request.form.get('e'))
        d = int(request.form.get('d'))
        p = int(request.form.get('p'))
        q = int(request.form.get('q'))
        saved = True

    context = {
        'n': n,
        'e': e,
        'd': d,
        'p': p,
        'q': q,
        'saved': saved
    }
    return render_template('enter_keys.html', **context)


@app.route('/crypto', methods=['GET', 'POST'])
def crypto():
    if n <= 0 or (e <= 0 and d <= 0):
        return index()
    context = {
        'n': n,
        'e': e,
        'd': d,
        'p': p,
        'q': q,
    }
    return render_template('crypto.html', **context)


@app.route('/crypto_number', methods=['GET', 'POST'])
def crypto_number():
    if request.method != 'POST':
        return crypto()
    input = int(request.form.get('input')) if request.form.get('input') else 0
    keytype = request.form.get('keytype')
    number_output_crt, time_needed_crt = None, None
    if keytype != 'private':
        keytype = 'public'
        # number_output = RSALibrary.encrypt_number(n, e, input)
        number_output, time_needed = timed_function_beautified(RSALibrary.encrypt_number, n, e, input)

    else:
        number_output, time_needed = timed_function_beautified(RSALibrary.encrypt_number, n, d, input)
        if p > 0 and q > 0:
            number_output_crt, time_needed_crt = timed_function_beautified(RSALibrary.decrypt_number_crt, d, p, q,
                                                                           input)

    context = {
        'n': n,
        'e': e,
        'd': d,
        'p': p,
        'q': q,
        'input': input,
        'number_output': number_output,
        'time_needed': time_needed,
        'number_output_crt': number_output_crt,
        'time_needed_crt': time_needed_crt,
        'keytype': keytype
    }
    return render_template('crypto.html', **context)


@app.route('/crypto_text', methods=['GET', 'POST'])
def crypto_text():
    if request.method != 'POST':
        return crypto()
    input_text = request.form.get('input_text')
    keytype = request.form.get('keytype')
    if keytype != 'private':
        keytype = 'public'
        text_output, time_needed = timed_function_beautified(RSALibrary.encrypt_text_v2, n, e, input_text)
    else:
        text_output, time_needed = timed_function_beautified(RSALibrary.encrypt_text_v2, n, d, input_text)

    context = {
        'n': n,
        'e': e,
        'd': d,
        'p': p,
        'q': q,
        'input_text': input_text,
        'text_output': text_output,
        'time_needed': time_needed,
        'keytype': keytype
    }
    return render_template('crypto.html', **context)


@app.route('/crypto_text_dec', methods=['GET', 'POST'])
def crypto_text_dec():
    if request.method != 'POST':
        return crypto()
    input_text_dec = int(request.form.get('input_text_dec')) if request.form.get('input_text_dec') else 0
    keytype = request.form.get('keytype')
    print(type(keytype))
    if keytype != 'private':
        keytype = 'public'
        text_output_dec, time_needed = timed_function_beautified(RSALibrary.decrypt_text_v2, n, e, input_text_dec)
    else:
        text_output_dec, time_needed = timed_function_beautified(RSALibrary.decrypt_text_v2, n, d, input_text_dec)

    context = {
        'n': n,
        'e': e,
        'd': d,
        'p': p,
        'q': q,
        'input_text_dec': input_text_dec,
        'text_output_dec': text_output_dec,
        'time_needed': time_needed,
        'keytype': keytype
    }

    return render_template('crypto.html', **context)


if __name__ == "__main__":
    port = 5000
    if len(sys.argv) > 1:
        port = sys.argv[1]
        if port.isnumeric():
            port = int(port)

    app.run(debug=True, port=port)  # listen on localhost ONLY
#    app.run(debug=True, host='0.0.0.0')    # listen on all public IPs

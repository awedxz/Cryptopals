import requests
import datetime
import operator

def main():
    win = False

    brute_force = '0' * 40
    byte_times = {}
    brute_idx = 0
    curr_byte = 0x00

    while not win:
        payload = {'file': 'breakme', 'signature': brute_force}
        time_list = []

        for i in range(1):
            start = datetime.datetime.now()
            r = requests.get('http://127.0.0.1:8081/crypto', params = payload)
            end = datetime.datetime.now()

            if r.status_code == 200:
                win = True

            diff = (end - start).total_seconds()
            time_list.append(diff)

        byte_times["{0:0{1}x}".format(curr_byte, 2)] = sum(time_list) / len(time_list)
        curr_byte += 1

        if curr_byte == 0x100:
            best = max(byte_times, key=byte_times.get)
            byte_times = {}
            s = list(brute_force)
            s[brute_idx] = best
            s[brute_idx + 1] = ''
            brute_force = "".join(s)
            brute_idx += 2
            curr_byte = 0
        else:
            s = list(brute_force)
            s[brute_idx] = "{0:0{1}x}".format(curr_byte, 2)
            s[brute_idx + 1] = ''
            brute_force = "".join(s)

        if brute_idx == 40:
            break

    print(win)

if __name__ == '__main__':
    main()

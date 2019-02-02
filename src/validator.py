from os import listdir

class Valid:
    def dynamic_code(self, id_client, num_bids, uploaded_code):
        local = {'id_client': id_client, 'num_bids': num_bids, 'valid': None}

        print("Dynamic Code  Execution Starting")
        code_to_execute = compile(uploaded_code, '<string>', 'exec')

        exec(code_to_execute, local)

        valid = local['valid']
        return valid


if __name__ == "__main__":
    # id_client=5
    test = Valid()

    id_client = '1'
    num_bids = 0
    name = 'restrict2.py'
    basename = "dynamicCode/"
    for filename in listdir(basename):
        if name in filename:
            with open(basename + name) as f:
                uploaded_code = f.read()

    print(uploaded_code)

    # filename="restrict2.py"

    valid = test.dynamic_code(id_client, num_bids, uploaded_code)
    print(valid)

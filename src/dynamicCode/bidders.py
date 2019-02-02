# this works
def foo(id_client, num_bids):
    valid_clients = ['WVzMbdOi9f+xgWZ5+jJ7TQ==', 'WuIaYf+KjvlGyJdCkGP7fA==']

    for i in range(0, len(valid_clients)):
        if id_client == valid_clients[i]:
            return True
    return False

valid = foo(id_client, num_bids)

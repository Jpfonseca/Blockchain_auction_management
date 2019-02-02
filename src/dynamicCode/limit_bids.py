# this works
def foo(id_client, num_bids):
    limit_bids = {'WVzMbdOi9f+xgWZ5+jJ7TQ==': 2, 'IzHRqoS1SirYWHLmtinmvw==': 1, 'WuIaYf+KjvlGyJdCkGP7fA==': 2}

    if id_client in limit_bids.keys():
        if num_bids <= limit_bids[id_client]:
                return True
    return False

valid = foo(id_client, num_bids)

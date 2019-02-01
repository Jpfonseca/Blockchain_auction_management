def foo(id_client, num_bids):
    valid_clients = ['1', '2', '4']
    limit_bids = {'1': 5, '2': 3, '4': 0}

    for i in range(0, len(valid_clients)):
        print(i)
        if id_client == valid_clients[i]:
            if num_bids <= limit_bids[valid_clients[i]]:
                return True

    return False


valid = foo(id_client, num_bids)

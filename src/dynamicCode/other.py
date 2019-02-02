valid_clients = ['1', '2', '4']

limit_bids = {'1': 0, '2': 3, '4': 0}

valid = False

for i in range(0, len(valid_clients)):
    if id_client == valid_clients[i]:
        if num_bids <= limit_bids[valid_clients[i]]:
            valid = True
            break

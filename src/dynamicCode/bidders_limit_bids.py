# this works
def foo(id_client, num_bids):
	valid_clients = ['WVzMbdOi9f+xgWZ5+jJ7TQ==', 'IzHRqoS1SirYWHLmtinmvw==', 'WuIaYf+KjvlGyJdCkGP7fA==']
	limit_bids = {'WVzMbdOi9f+xgWZ5+jJ7TQ==': 1, 'IzHRqoS1SirYWHLmtinmvw==': 2, 'WuIaYf+KjvlGyJdCkGP7fA==': 1}

	for i in range(0, len(valid_clients)):
		if id_client == valid_clients[i]:
			if num_bids <= limit_bids[id_client]:
				return True
	return False

valid = foo(id_client, num_bids)
import time


def query_all(table, **query):
    """Return every result from `table` by evaluating `query`.

    Perform a table scan instead if `query` is empty.
    """
    if query:
        res = table.query(**query)
    else:
        res = table.scan()

    items = res["Items"]

    while "LastEvaluatedKey" in res:
        time.sleep(1)  # Let's be nice

        if query:
            res = table.query(ExclusiveStartKey=res["LastEvaluatedKey"], **query)
        else:
            res = table.scan(ExclusiveStartKey=res["LastEvaluatedKey"])

        items.extend(res["Items"])

    return items

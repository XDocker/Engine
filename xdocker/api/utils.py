def remove_doc_id(doc):
    try:
        del doc['_id']
    except StandardError:
        pass
    return doc


def rename_doc_id(doc):
    doc['oid'] = doc.pop('_id')
    return doc

from app import db, User, Art, Transaction

art = Art.query.filter_by(id=1).first()
print(art.transactions)
for transaction in art.transactions:
    print(transaction)
    print(transaction.seller_id)
    print(transaction.buyer_id)
    print(transaction.art)
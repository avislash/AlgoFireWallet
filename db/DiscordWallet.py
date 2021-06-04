from mongoengine import Document, StringField, LongField
class DiscordWallet(Document):
    userId = LongField(required=True)
    address = StringField(required=True)
    ppk = StringField(required=True)

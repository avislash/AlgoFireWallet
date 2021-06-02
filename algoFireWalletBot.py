import discord
from discord.ext import commands
from mongoengine import connect
from mongoengine import Document, StringField, LongField
from algosdk import account, mnemonic
from algosdk.future import transaction
from algosdk.v2client import algod, indexer
import requests
import json
import time

intents = discord.Intents.default()
intents.members = True
bot = commands.Bot(command_prefix='!', intents=intents)
algoNode = algod.AlgodClient(nodeToken, nodeAddr)
#purestakeUrl = "https://mainnet-algorand.api.purestake.io/idx"
purestakeUrl = "https://testnet-algorand.api.purestake.io/idx2"
algoIndexer = indexer.IndexerClient(indexer_token="", indexer_address=purestakeUrl, headers=purestakeHeader)
class DiscordWallet(Document):
    userId = LongField(required=True)
    address = StringField(required=True)
    ppk = StringField(required=True)

def wait_for_confirmation(client, transaction_id, timeout):
    start_round = client.status()["last-round"]+1;
    current_round = start_round

    while current_round < start_round + timeout:
        try:
            pending_txn = client.pending_transaction_info(transaction_id)
        except Exception:
            return
        if pending_txn.get("confirmed-round", 0) > 0:
            return pending_txn
        elif pending_txn["pool-error"]:
            raise Exception( 'pool error: {}'.format(pending_txn["pool-error"]))
        client.status_after_block(current_round)
        current_round += 1
    raise Exception('pending tx not found in timeout rounds, timeout value = : {}'.format(timeout))

def getAssetInfo(assetId):
   #The Indexer must be used to get ASA Meta data such as unit-name and
   #this requires an archival node. Instead of running my own archical ndoe
   #I instead grab this information using the AlgoExploer API
   asset_info = {}
   try:
       #algoExplorerAssetUrl = "https://api.algoexplorer.io/idx2/v2/assets/"
       algoExplorerAssetUrl = "https://testnet.algoexplorerapi.io/idx2/v2/assets/"
       algoExplorerAssetUrl= algoExplorerAssetUrl + str(assetId)
       
       asset_info = json.loads(requests.get(algoExplorerAssetUrl).text)
   except Exception as e:
       #print(e)
       pass

   return asset_info

def parseArgs(args):
   argsDict = {}
   for arg in args:
       try:
           argsDict[arg.split("=")[0].lstrip(' ').lower()] = arg.split("=")[1].lstrip(' ')
       except:
           pass
   return argsDict
    
def generate_algorand_keypair():
    return account.generate_account()

@bot.event
async def on_ready():
    print(f'{bot.user.name} has connected to Discord!')

@bot.event
async def on_member_join(member):
   if not DiscordWallet.objects(userId=member.id):
       [ppk, address] = generate_algorand_keypair()
       wallet = DiscordWallet(userId = member.id, address = address, ppk=ppk)
       wallet.save()
       await member.create_dm()
       await member.send("Welcome to {}. A New Algorand Wallet has been created for you with the address : {}".format(member.guild, address))
       await member.send("Type !help to see list of available commands")
   else:
       await member.create_dm()
       await member.send("Welcome to {}. Found existing Algorand Wallet with address {}".format(member.guild, DiscordWallet.objects(userId=member.id)[0]['address']))
       await member.send("Type !help to see list of available commands")
       #print("User exists")

@bot.command(name='mkWallet', help="Creates wallet if one doesn't exist")
async def make_wallet(ctx):
     #print(ctx.message.channel)
     #print(ctx.author.id)
     if not DiscordWallet.objects(userId=ctx.author.id):
         [ppk, address] = generate_algorand_keypair()
         wallet = DiscordWallet(userId = ctx.author.id, address = address, ppk=ppk)
         wallet.save()
         await ctx.author.send("New Wallet Created: {}".format(address))
         await ctx.message.channel.send("New Wallet Created for {0.author}".format(ctx))
     else:
         await ctx.message.channel.send("Wallet already exists for {0.author}".format(ctx))

@bot.command(name='seed', help="Get 25 word mnemonic")
async def get_seed(ctx):
   if not DiscordWallet.objects(userId__exists=ctx.author.id):
       await ctx.message.channel.send("No wallet exists for {0.author}. Create one using !mkWallet".format(ctx))
   else:
       ppk = DiscordWallet.objects(userId=ctx.author.id)[0]['ppk']
       await ctx.author.send("25 Word mnemonic seed: {}".format(mnemonic.from_private_key(ppk)))
       if not isinstance(ctx.message.channel, discord.channel.DMChannel):
           await ctx.message.channel.send("Attention {0.author} Check DM for seed phrase".format(ctx) )

@bot.command(name='address', help="Display Public Address")
async def get_address(ctx):
   if not DiscordWallet.objects(userId__exists=ctx.author.id):
       await ctx.message.channel.send("No wallet exists for {0.author}. Create one using !mkWallet".format(ctx))
   else:
       address = DiscordWallet.objects(userId=ctx.author.id)[0]['address']
       await ctx.message.channel.send("{}'s address: {}".format(ctx.author, address))

@bot.command(name='mint', help="Create an ASA")
async def mint(ctx):
   if not DiscordWallet.objects(userId=ctx.author.id):
       await ctx.channel.send("No wallet exists for {0.author}. Create one using !mkWallet".format(ctx))
       return
   #print(ctx.message.content)
   #Parse Message for asset params
   try:
       args = ctx.message.content.lstrip("!mint").split(",")
       assetParams = {}
       wallet = DiscordWallet.objects(userId=ctx.author.id)

       address = wallet[0]['address'] #DiscordWallet.objects(userId=ctx.author.id)[0]['address']
       #print("Address {}".format(address))
       assetParams = parseArgs(args)
       #for arg in args:
       #    assetParams[arg.split("=")[0].lstrip(' ').lower()] = arg.split("=")[1].lstrip(' ')
           
       #validate args
       #print("Validating args")
       try:
           if not 'total' in assetParams:
               raise Exception("total")
           elif not 'decimals' in assetParams:
               raise Exception("decimals")
           #elif not 'frozen' in assetParams:
           #    raise Exception("frozen")
       except Exception as missingArg:
           await ctx.channel.send("Error Minting tokens for {0.author}. Missing {} arg".format(ctx, missingArg))
           return
       
       #Fill in missing parameters
       #print("Args Validated")
       if not 'frozen' in assetParams:
           assetParams['frozen'] = False
       else:
           assetParams['frozen'] = bool(assetParams['frozen'])
       if not 'freezeaddr' in assetParams:
           assetParams['freezeaddr'] = address
       else:
           if "null" == assetParams['freezeaddr'].lower():
               assetParams['freezeaddr'] = None
       if not 'assetname' in assetParams:
           assetParams['assetname'] = ""
       if not 'unitname' in assetParams:
           asseParams['unitname'] = ""
       if not 'url' in assetParams:
           assetParams['url'] = ""
       if not 'metadata' in assetParams:
           assetParams['metadata'] = ""
       if not "clawback" in assetParams:
           assetParams["clawback"] = address
       else:
           if "null" == assetParams['clawback'].lower():
               assetParams['clawback'] = None

           
       #print("Getting network params")
       try:
           networkParams = algoNode.suggested_params()
       except Exception as e:
           await ctx.channel.send("Error Minting tokens for {0.author}. Failed to retrieve Algorand Network parameters".format(ctx))
           print(e)
           return
           #print("Failed to get network params")
       #print("Calling asset config txn")
       try:
           aTxn = transaction.AssetConfigTxn( sender=address,
                                              sp = networkParams,
                                              default_frozen=assetParams['frozen'],
                                              unit_name=assetParams['unitname'],
                                              asset_name=assetParams['assetname'],
                                              total = int(assetParams['total']),
                                              manager = address,
                                              reserve = address,
                                              freeze = assetParams['freezeaddr'],
                                              clawback=assetParams['clawback'],
                                              decimals = int(assetParams['decimals']),
                                              url = assetParams['url'],
                                              strict_empty_address_check=False
                                            )
       except Exception as e:
           await ctx.channel.send("Error Minting tokens for {0.author}. Failed to Generate AssetConfigTxn: {1}".format(ctx, e))
           print(e)
           return

       #print("aTxn created")
       sATxn = aTxn.sign(wallet[0]['ppk'])
       #print('aTxn signed')
       try:
           txid = algoNode.send_transaction(sATxn)
           wait_for_confirmation(algoNode, txid, 5)
       except Exception as e:
           await ctx.channel.send("Error Minting tokens for {0.author}. Failed to submit txn to Algorand Network: {1}".format(ctx, e))
           print(e)
           #print("Failed to send transaction")
       try:
           ptx = algoNode.pending_transaction_info(txid)
           assetId = ptx["asset-index"]
           await ctx.channel.send("{0.author} successfully minited asset id #{1}".format(ctx, assetId))
       except Exception as e:
           await ctx.channel.send("Error Minting tokens for {0.author}: {1}".format(ctx, e))
           print(e)
                                      
   except Exception as e:
       await ctx.channel.send("Error Minting tokens for {0.author}: {1}".format(ctx,e))
       print(e)

@bot.command(name="add-asa", help="Add ASA to account")
async def optin(ctx, asaId: int):
   wallet = DiscordWallet.objects(userId=ctx.author.id)
   if not wallet:
       await ctx.channel.send("No wallet exists for {0.author}. Create one using !mkWallet".format(ctx))
       return
   else:
       wallet = wallet[0]

   assetInfo = getAssetInfo(asaId)
   if not 'asset' in assetInfo:
       await ctx.channel.send("Unable to add ASA ID #{} for {}: ASA does not exist".format(asaId, ctx.author))
       return

   accountInfo = algoNode.account_info(wallet['address'])

   for asset in accountInfo['assets']:
       if asaId == asset['asset-id']:
           message = "Already opted into {} (ASA ID#{})".format(assetInfo['asset']['params']['unit-name'], asaId)
           if not isinstance(ctx.message.channel, discord.channel.DMChannel):
               message = "{} ".format(ctx.author) + message
           await ctx.channel.send(message)
           return 
   try:
       unsigned_optin_txn = transaction.AssetTransferTxn(sender=wallet['address'], sp=algoNode.suggested_params(), receiver=wallet['address'], amt=0, index=asaId)
       signed_optin = unsigned_optin_txn.sign(wallet['ppk'])

       txid = algoNode.send_transaction(signed_optin)
       wait_for_confirmation(algoNode, txid, 5)
       message = "Succesfully added {} (ASA ID#{})".format(assetInfo['asset']['params']['unit-name'], asaId)

       if not isinstance(ctx.message.channel, discord.channel.DMChannel):
           message = message + " for {}".format(ctx.author)
 
       await ctx.channel.send(message)
   except Exception as e:
       message = "Unable to add ASA ID#{}"

       if not isinstance(ctx.message.channel, discord.channel.DMChannel):
           message = message + "for {}".format(ctx.author)
       message = message + ": {}".format(e)
       await ctx.channel.send(message)


@bot.command(name="remove-asa", help="Remove ASA from account")
async def optout(ctx, asaId: int):
   wallet = DiscordWallet.objects(userId=ctx.author.id)
   if not wallet:
       await ctx.channel.send("No wallet exists for {0.author}. Create one using !mkWallet".format(ctx))
       return
   
   wallet = wallet[0]
   account_info = algoNode.account_info(wallet['address'])

   try:
       for asset in account_info['assets']:
           if asaId == asset['asset-id']:
               break
           else:
               asset={}

       if not asset:
           message = "Asset #{} not found in current holdings".format(asaId)
           if not isinstance(ctx.message.channel, discord.channel.DMChannel):
               message = message + " for {}".format(ctx.author)
           await ctx.channel.send(message)
           return
       else:
           #TODO put all this in sendAsa() function
           params = algoNode.suggested_params()
           if asset['creator'] != wallet['address']:
               asaTxn = transaction.AssetTransferTxn(wallet['address'], params, wallet['address'], 0, asset['asset-id'], close_assets_to=asset['creator'])
           else:
               asaTxn = transaction.AssetConfigTxn(sender=wallet['address'], sp=params, index=asset['asset-id'], strict_empty_address_check=False)

           sAsaTxn = asaTxn.sign(wallet['ppk'])
           txid = algoNode.send_transaction(sAsaTxn)
           try:
               wait_for_confirmation(algoNode, txid, 5)
               txn_resp = algoNode.pending_transaction_info(txid)
               await ctx.channel.send("{} Successfully opted out of ASA ID# {}".format(ctx.author, asaId))
           except Exception as e:
               await ctx.channel.send("{} Unable to opt out of ASA ID# {}: {}".format(ctx.author, asaId, e))
               print(e)
                
   except Exception as e:
       await ctx.channel.send("{} Unable to opt out of ASA ID# {}: {}".format(ctx.author, asaId, e))
       print(e)
       
@bot.command(name="sendASA", help="Send Algorand ASA to Discord User")
async def send_asa(ctx, amount:float, asaId:int, username:str, *, note:str=""):
   senderWallet = DiscordWallet.objects(userId=ctx.author.id)
   if not senderWallet:
       await ctx.channel.send("No wallet exists for {0.author}. Create one using !mkWallet".format(ctx))
       return
  

   if note:
       encodedNote = note.encode()
   else:
       encodedNote = None

   recipientId = int(username.strip("!@<>"), base=10)
   recipient = bot.get_user(recipientId)
   senderWallet = senderWallet[0]
   optRecipientIn = True
   newWallet = False
   recipientWallet  = DiscordWallet.objects(userId=recipientId)
   
   #Make sure sender is opted into asset they're trying to send
   account_info = algoNode.account_info(senderWallet['address'])
   foundAsset = False
   for asset in account_info['assets']:
       if asaId == asset['asset-id']:
           foundAsset = True
           break
   if not foundAsset:
       await ctx.channel.send("ASA ID #{} not found in {}'s holdings".format(asaId, ctx.author))
       return

   if not recipientWallet:
       [ppk, address] = generate_algorand_keypair()
       wallet = DiscordWallet(userId = recipientId, address = address, ppk=ppk)
       wallet.save()
       recipientWallet = DiscordWallet.objects(userId=recipientId)[0]
       neww_wallet = True
       await recipient.send("New Wallet Created: {}".format(address))
       await ctx.message.channel.send("New Wallet Created for {0.name}".format(recipient))
   else:
       recipientWallet = recipientWallet[0]
       account_info = algoNode.account_info(recipientWallet['address'])

       for asset in account_info['assets']:
           if asaId == asset['asset-id']:
               optRecipientIn = False
               break
   assetInfo = getAssetInfo(asaId)

   asaTxferGroup=[] #Order will always be Send .001 Algo to opt user in, opt user in, send ASA
   try:
       params = algoNode.suggested_params()
   except Exception as e:
       await ctx.message.channel.send("Attention {} ASA ID#{} Send to {} Failed: Unable to get Algorand Network Params: {}".format(ctx.author, asaId, username,e))

   if True == optRecipientIn:
       #For auto opt-in send the algo to cover the opt-in as well as the minmum balance required
       try:
           optin_fee = 0.001 #Algo
           minimum_balance_increase = .100#Algo
           new_wallet_min_balance = .100#Algo

           amount_to_send = optin_fee + minimum_balance_increase + (new_wallet_min_balance if True == newWallet else 0)
           amount_to_send = int(amount_to_send*1e6)
           #print("Sending {} ALGO to allow for optin".format(amount_to_send))
           #unsigned_tx = transaction.PaymentTxn(senderAddr, params, recipientAddr, amount_to_send, None)
           #print(amount_to_send)
           unsigned_optin_fee_txn = transaction.PaymentTxn(senderWallet['address'], params, recipientWallet['address'], amount_to_send, None, note="Optin fee".encode())
           asaTxferGroup.append(unsigned_optin_fee_txn)
           unsigned_optin_txn = transaction.AssetTransferTxn(sender=recipientWallet['address'], sp=params, receiver=recipientWallet['address'], amt=0, index=asaId)
           asaTxferGroup.append(unsigned_optin_txn)
       except Exception as e:
           await ctx.message.channel.send("Attention {} Unable to send {} {} (ASA ID# {}) to {} Failed to  generate optin xfer group: {}".format(ctx.author, amount, assetInfo['asset']['params']['unit-name'], asaId, username, e))
           return

   #print(assetInfo)
   decimals = assetInfo['asset']['params']['decimals']
   asaAmtToSend = int(amount * (10**decimals))
   
   try:
       unsigned_asaTxfer = transaction.AssetTransferTxn(sender=senderWallet['address'], sp=params, receiver=recipientWallet['address'], amt=asaAmtToSend, index=asaId, note=encodedNote)
       asaTxferGroup.append(unsigned_asaTxfer)
   except Exception as e:
       print("Failed to make final asaTxfer: {}".format(e))
       return
   
   #Group all transactions up, then send them
   txid = {}
   try:
       if len(asaTxferGroup) > 1:
           signed_group = []
           gid = transaction.calculate_group_id(asaTxferGroup)
           asaTxferGroup[0].group = gid
           asaTxferGroup[1].group = gid
           asaTxferGroup[2].group = gid

           
           signed_group.append(asaTxferGroup[0].sign(senderWallet['ppk']))
           signed_group.append(asaTxferGroup[1].sign(recipientWallet['ppk']))
           signed_group.append(asaTxferGroup[2].sign(senderWallet['ppk']))
           txid = algoNode.send_transactions(signed_group)
       else:
           signedAsaXfer = asaTxferGroup[0].sign(senderWallet['ppk'])
           txid = algoNode.send_transaction(signedAsaXfer)
   except Exception as e:
       await ctx.channel.send("Attention {} Error sending ASA ID #{} to {} : {}".format(ctx.author, asaId, username, e))
       return

   try:
       wait_for_confirmation(algoNode, txid, 5)
       await ctx.channel.send("{} sent {} {} to {}".format(ctx.author, (asaAmtToSend*10**(-1*decimals)), assetInfo['asset']['params']['unit-name'], username))
       await recipient.send("{} sent you {} {} ASA ID#{} {}".format(ctx.author, asaAmtToSend*10**(-1*decimals),assetInfo['asset']['params']['unit-name'], asaId, ("with note: {}".format(note) if note else ""  )))
   except Exception as e:
       await ctx.channel.send("Attention {} Error sending ASA ID #{} to {} : {}".format(ctx.author, asaId, username, e))
     

@bot.command(name='balance', help="Get Algorand Account Balance")
async def get_balance(ctx, flex:str=""):
   if not DiscordWallet.objects(userId=ctx.author.id):
       await ctx.channel.send("No wallet exists for {0.author}. Create one using !mkWallet".format(ctx))
   else:
       address = DiscordWallet.objects(userId=ctx.author.id)[0]['address']
       account_info = algoNode.account_info(address)
       amount = account_info.get('amount')*1e-6
       suffix = "ALGO" #"Algos" if amount != 1 else "Algo"
       coins = [str(format(amount,'.6f'))+ " " + suffix]
       for asset in account_info['assets']:
           try:
               amount = asset['amount']

               assetInfo = getAssetInfo(asset['asset-id'])
               #assetInfo = algoIndexer.asset_info(asset['asset-id'])
               #print(assetInfo)
               decimals = assetInfo['asset']['params']['decimals']
               scaleFactor = 10 ** (-1*decimals)
               amount = amount*scaleFactor
               coins.append("{} {} (Asset ID #{})".format(format(amount, '.{}f'.format(decimals)), assetInfo['asset']['params']['unit-name'], asset['asset-id']))
               #coins.append(str(amount) +" "+ assetInfo['asset']['params']['unit-name'])
           except Exception as e:
               print(e)
               coins.append("Unable to get Balance for Asset ID {}".format(asset['asset-id']))
           #break
           #time.sleep(1)

       acctBalance = "\n ".join(coins)
       if "flex" == flex.lower():
           #await ctx.message.channel.send("Current Balance: {} {}".format(amount, suffix))
           await ctx.message.channel.send("{}'s Current Balance:\n {}".format(ctx.author, acctBalance))
           #for coin in coins:
           #    await ctx.message.channel.send(coin)
       else:
           await ctx.author.send("Current Balance:\n {}".format(acctBalance))
           if not isinstance(ctx.message.channel, discord.channel.DMChannel):
               await ctx.message.channel.send("Attention {0.author} Check DM for account balance".format(ctx) )

@bot.command(name='sendAlgo', help="Send Algo to Discord user")
async def send_algo(ctx, algo: float,  username: str, *, note:str=""):
   if not DiscordWallet.objects(userId=ctx.author.id):
       await ctx.channel.send("No wallet exists for {0.author}. Create one using !mkWallet".format(ctx))
       return
   #print(algo)
   #print(username)
   #print(note)

   if note:
       encodedNote = note.encode()
   else:
       encodedNote = None

   userId = int(username.strip("!@<>"), base=10)
   #print(username)
   recipient = bot.get_user(userId)
   await recipient.create_dm()

   amount_to_send = int(algo*1e6)
   params = algoNode.suggested_params()
   senderWallet = DiscordWallet.objects(userId=ctx.author.id)[0]
   senderAddr = senderWallet['address']

   if not DiscordWallet.objects(userId=userId):
       [ppk, address] = generate_algorand_keypair()
       wallet = DiscordWallet(userId = recipient.id, address = address, ppk=ppk)
       wallet.save()
       await recipient.send("New Wallet Created: {}".format(address))
       await ctx.message.channel.send("New Wallet Created for {0.name}".format(recipient))

   recipientAddr = DiscordWallet.objects(userId=userId)[0]['address']
   unsigned_tx = transaction.PaymentTxn(senderAddr, params, recipientAddr, amount_to_send, None, note=encodedNote)
   signed_tx = unsigned_tx.sign(senderWallet['ppk'])

   try:
       txid = algoNode.send_transaction(signed_tx)
       wait_for_confirmation(algoNode, txid, 5)
       await recipient.send("{} sent you {} ALGO {}".format(ctx.author, algo, ("with note: {}".format(note) if note else "" )))
       await ctx.message.channel.send("{} Sent {} ALGO to {}".format(ctx.author, algo, username))
   except Exception as err:
       await ctx.message.channel.send("Attention {} failed to send {} Algo to {}: {}".format(ctx.author, algo, username, err))

@bot.command(name="withdrawAlgo", help="Send ALGO to external Algorand Account")
async def withdraw_algo(ctx, amount: float, address: str, *, note:str=""):
   wallet = DiscordWallet.objects(userId=ctx.author.id)
   if not wallet:
       await ctx.channel.send("No wallet exists for {0.author}. Create one using !mkWallet".format(ctx))
       return
   else:
       wallet = wallet[0]

   if note:
       encodedNote = note.encode()
   else:
       encodedNote = None

   amount_to_send = int(amount*1e6)
   params = algoNode.suggested_params()
   unsigned_tx = transaction.PaymentTxn(wallet['address'], params, address, amount_to_send, None, note=encodedNote)
   signed_tx = unsigned_tx.sign(wallet['ppk'])
   
   try:
       txid = algoNode.send_transaction(signed_tx)
       wait_for_confirmation(algoNode, txid, 5)
       await ctx.message.channel.send("{} Sent {} ALGO to {}".format(ctx.author, amount, address))
   except Exception as err:
       await ctx.message.channel.send("Attention {} failed to send {} ALGO to {}: {}".format(ctx.author, amount, address, err))
   
@bot.command(name="withdrawASA", help="Send Algorand ASA to external Algorand Account")
async def withdrawASA(ctx, amount: float,  asaId: int, address: str, *, note:str=""):
   wallet = DiscordWallet.objects(userId=ctx.author.id)
   if not wallet:
       await ctx.channel.send("No wallet exists for {0.author}. Create one using !mkWallet".format(ctx))
       return
   else:
       wallet = wallet[0]

   if note:
       encodedNote = note.encode()
   else:
       encodedNote = None

   #Make sure sender is opted into asset they're trying to send
   account_info = algoNode.account_info(wallet['address'])
   foundAsset = False
   for asset in account_info['assets']:
       if asaId == asset['asset-id']:
           foundAsset = True
           break
   if not foundAsset:
       await ctx.channel.send("ASA ID #{} not found in {}'s holdings".format(asaId, ctx.author))
       return

   assetInfo = getAssetInfo(asaId)
   decimals = assetInfo['asset']['params']['decimals']
   asaAmtToSend = int(amount * (10**decimals))
   #print("Address len {}".format(len(address)))
   try:
       unsigned_asaXfer = transaction.AssetTransferTxn(sender=wallet['address'], sp=algoNode.suggested_params(), receiver=address, amt=asaAmtToSend, index=asaId, note=encodedNote)
       signed_asaXfer = unsigned_asaXfer.sign(wallet['ppk'])

       txid = algoNode.send_transaction(signed_asaXfer)
       wait_for_confirmation(algoNode, txid, 5)
       await ctx.channel.send("{} sent {} {} (ASA ID{}) to {}".format(ctx.author, asaAmtToSend*(10**(-1*decimals)), assetInfo['asset']['params']['unit-name'], asaId, address))
   except Exception as err:
       print(err)
       await ctx.channel.send("{} Error Sending {} {} (ASA ID{}) to {}:{}".format(ctx.author, asaAmtToSend*(10**(-1*decimals)), assetInfo['asset']['params']['unit-name'], asaId, address, err))

bot.run(TOKEN)

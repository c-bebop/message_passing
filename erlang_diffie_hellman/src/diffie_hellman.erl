%%% @author     Florian Willich
%%% @copyright  The MIT License (MIT) for more information see
%%%             http://opensource.org/licenses/MIT
%%% @doc        This module represents a simple implementation of the
%%%             Diffie-Hellman key exchange algorithm.
%%% @end
%%% Created 2015-06-06

-module(diffie_hellman).
-author("Florian Willich").
-compile(export_all).

%%% @doc  Public data represents the data which is publicly shared within two
%%%       communication partners when exchanging key by the Diffie-Hellman key
%%%       exchange algorithm.
%%%       p: The public prime number
%%%       g: The public prime number (1 ... p - 1)
%%%       componentKey: The computed component key
%%%       pid: The pid of the one who instantiated this record
-record(publicData, {p, g, componentKey, pid}).

%%% @doc  Returns the value G to the power of MySecretKey Modulo P which is the
%%%       public component key for the Diffie-Hellman key exchange algorithm.
%%%       For more information see http://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
%%% @end
-spec computeMyPublicComponentKey(pos_integer(), pos_integer(), pos_integer()) -> pos_integer().
computeMyPublicComponentKey(P, G, MySecretKey) ->
  my_math:pow(G, MySecretKey) rem P.

%%% @doc  Returns the value ComponentKey to the power of MySecretKey Modulo P
%%%       which is the private shared key for the Diffie-Hellman key exchange
%%%       algorithm.
%%%       For more information see http://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
%%% @end
-spec computeSharedPrivateKey(pos_integer(), pos_integer(), pos_integer()) -> pos_integer().
computeSharedPrivateKey(P, ComponentKey, MySecretKey) ->
  my_math:pow(ComponentKey, MySecretKey) rem P.

%%% @doc  Starts the Diffie-Hellman key exchange algorithm by taking P (a prime 
%%%       number), G (1 ... P - 1), MySecretKey is the secret integer of the
%%%       one who executes this function and the PartnerPID which is the PID of
%%%       the communication partner with you a key exchange shall be initiated.
%%%       This function sends the term {startKeyExchange, PublicData} to the
%%%       PartnerPID where PublicData is of type publicData.
%%%       Afterwards, the function starts a receive construct which is receiving
%%%       the following:
%%%       {componentKey, PublicData}: The message including all information
%%%                                   needed for computing the private shared
%%%                                   key and then prints it out.
%%%       UnexpectedMessage:          Prints out any unexpected incomping
%%%                                   message and calls a recursion.
%%%       After 3000 milliseconds:    The function will return timeout.
%%% @end
-spec startKeyExchange(pos_integer(), pos_integer(), pos_integer(), term()) -> term().
startKeyExchange(P, G, MySecretKey, PartnerPID) ->
  MyComponentKey = computeMyPublicComponentKey(P, G, MySecretKey),
  MyPublicData = #publicData{p = P, g = G, componentKey = MyComponentKey, pid = self()},
  PartnerPID ! {startKeyExchange, MyPublicData},

  receive

    {componentKey, #publicData{p = P, g = G, componentKey = PartnerComponentKey, pid = PartnerPID}} ->
      PrivateSharedKey = computeSharedPrivateKey(P, PartnerComponentKey, MySecretKey),
      printSharedPrivateKey(self(), PrivateSharedKey);

    UnexpectedMessage ->
      printUnexpectedMessage(UnexpectedMessage),
      startKeyExchange(P, G, MySecretKey, PartnerPID)

  after 3000 ->
    timeout

  end.

%%% @doc  Listens on Messages to start the Diffie-Hellman key exchange by
%%%       starting the following receive construct:
%%%       {startKeyExchange, PublicData}: The message including all information
%%%                                       needed to start the key exchange by
%%%                                       computing the own public data which
%%%                                       will then be send to the PartnerPID
%%%                                       as follows: {componentKey, MyPublicData}.
%%%                                       Afterwards, the private shared key
%%%                                       will be printed out and the function
%%%                                       calls a recursion.
%%%       terminante:                     Prints out that this function
%%%                                       terminates with the executing PID and
%%%                                       returns ok.
%%%       UnexpectedMessage:              Prints out any unexpected incomping
%%%                                       message and calls a recursion.
-spec listenKeyExchange(pos_integer()) -> term().
listenKeyExchange(MySecretKey) ->
  receive

    {startKeyExchange, #publicData{p = P, g = G, componentKey = PartnerComponentKey, pid = PartnerPID}} ->
      MyComponentKey    = computeMyPublicComponentKey(P, G, MySecretKey),
      MyPublicData      = #publicData{p = P, g = G, componentKey = MyComponentKey, pid = self()},
      PartnerPID ! {componentKey, MyPublicData},
      PrivateSharedKey  = computeSharedPrivateKey(P, PartnerComponentKey, MySecretKey),
      printSharedPrivateKey(self(), PrivateSharedKey),
      listenKeyExchange(MySecretKey);

    terminate ->
      io:format("~p terminates!~n", [self()]),
      ok;

    UnexpectedMessage ->
      printUnexpectedMessage(UnexpectedMessage),
      listenKeyExchange(MySecretKey)

  end.

%%% @doc  Prints out the UnexpectedMessage as follows:
%%%       Received an unexpected message: 'Unexpected Message'
%%% @end
printUnexpectedMessage(UnexpectedMessage) ->
  io:format("Received an unexpected message: ~p~n", [UnexpectedMessage]).

%%% @doc  Prints out the shared private key as follows:
%%%       'PID': The shared private Key is: 'SharedKey'
%%% @end
printSharedPrivateKey(PID, SharedKey) ->
  io:format("~p: The shared private Key is: ~p~n", [PID, SharedKey]).

%%% @doc  Starts a key exchange example by spawning the Alice process, which
%%%       executes the listenKeyExchange function with MySecretKey = 15, and
%%%       the Bob process, which exectues the startKeyExchange function with
%%%       P = 23, G = 5, MySecretKey = 6 and PartnerPID = Alice.
%%%       Returns Alice and Bob.
%%%
startExample() ->
  Alice   = spawn(diffie_hellman, listenKeyExchange, [15]),
  Bob = spawn(diffie_hellman, startKeyExchange, [23, 5, 6, Alice]),
  {Alice, Bob}.

%%% @doc  Starts a key exchange remote example by spawning the Alice process,
%%%       which executes the listenKeyExchange function with MySecretKey = 15,
%%%       and the Bob process, located on the RemoteNode, which exectues the
%%%       startKeyExchange function with P = 23, G = 5, MySecretKey = 6 and
%%%       PartnerPID = Alice.
%%%       Returns Alice and Bob.
%%% @end
startRemoteExample(RemoteNode) ->
  Alice   = spawn(RemoteNode, diffie_hellman, listenKeyExchange, [15]),
  Bob = spawn(diffie_hellman, startKeyExchange, [23, 5, 6, Alice]),
  {Alice, Bob}.
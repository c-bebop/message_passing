%%% @author     Florian Willich
%%% @copyright  The MIT License (MIT) Copyright (c) 2014 
%%%             University of Applied Sciences, Berlin, Germany
%%%             Florian Willich
%%%             For more detailed information, please read the 
%%%             licence.txt in the erlang root directory.
%%% @doc        This module represents a simple implementation of
%%%             the Diffie-Hellman key exchange algorithm and is
%%%             part of my technical report 'Introductory Guide
%%%             to Message Passing in Distributed Systems'.
%%%             More information can be found on:
%%% https://en.wikipedia.org/wiki/Diffie–Hellman_key_exchange 
%%% @end
%%% Created 2015-06-06

-module(diffie_hellman).
-author("Florian Willich").
-export([ computeMyPublicComponentKey/3, 
          computeSharedPrivateKey/3, 
          startKeyExchange/5, 
          listenKeyExchange/2, 
          startExample/0, 
          startRemoteExample/1,
          startRemoteExample/5]).

%%% @doc  Public data represents the data which is publicly shared 
%%%       within two communication partners when exchanging keys
%%%       with the Diffie-Hellman key exchange algorithm.
%%%       p: The public prime number
%%%       g: The public prime number (1 ... p - 1)
%%%       componentKey: The computed component key
%%%       pid: The pid of the one who instantiated this record
%%%       name: The name of whom creates this public data.
-record(publicData, {p, g, componentKey, pid, name}).

%%% @doc  Returns the value G to the power of MySecretKey Modulo P 
%%%       which is the public component key for the Diffie-Hellman 
%%%       key exchange algorithm. 
%%% @end
-spec computeMyPublicComponentKey(pos_integer(), pos_integer(), pos_integer()) -> pos_integer().
computeMyPublicComponentKey(P, G, MySecretKey) ->
  my_math:pow(G, MySecretKey) rem P.

%%% @doc  Returns the value ComponentKey to the power of 
%%%       MySecretKey Modulo P which is the private
%%%       shared key for the Diffie-Hellman key exchange
%%%       algorithm.
%%% @end
-spec computeSharedPrivateKey(pos_integer(), pos_integer(), pos_integer()) -> pos_integer().
computeSharedPrivateKey(P, ComponentKey, MySecretKey) ->
  my_math:pow(ComponentKey, MySecretKey) rem P.

%%% @doc  Starts the Diffie-Hellman key exchange algorithm by 
%%%       taking P (a prime number), G (1 ... P - 1), MySecretKey
%%%       is the secret integer of the one who executes this 
%%%       function and the PartnerPID which is the PID of the 
%%%       communication partner with whom a key exchange shall be
%%%       initiated.  MyName shall be the name of the executing
%%%       partner. This function sends the term
%%%       {startKeyExchange, PublicData} to the PartnerPID where 
%%%       PublicData is of type publicData. Afterwards, the 
%%%       function starts a receive construct which is receiving 
%%%       the following:
%%%       {componentKey, PublicData}: 
%%%           The message including all information needed for 
%%%           computing the private shared key and then prints it
%%%           out.
%%%       UnexpectedMessage:          
%%%           Prints out any unexpected incoming message and 
%%%           calls a recursion.
%%%       After 3000 milliseconds:    
%%%           The function will return timeout.
%%% @end
-spec startKeyExchange(pos_integer(), pos_integer(), pos_integer(), term(), string()) -> term() | {error, atom()}.
startKeyExchange(P, G, MySecretKey, PartnerPID, MyName) ->
  MyComponentKey = computeMyPublicComponentKey(P, G, MySecretKey),
  MyPublicData = #publicData{p = P, g = G, componentKey = MyComponentKey, pid = self(), name = MyName},
  PartnerPID ! {startKeyExchange, MyPublicData},

  receive

    {componentKey, #publicData{p = P, g = G, componentKey = PartnerComponentKey, pid = PartnerPID, name = PartnerName}} ->
      PrivateSharedKey = computeSharedPrivateKey(P, PartnerComponentKey, MySecretKey),
      printSharedPrivateKey(self(), MyName, PartnerName, PrivateSharedKey);

    UnexpectedMessage ->
      printUnexpectedMessage(UnexpectedMessage),
      startKeyExchange(P, G, MySecretKey, PartnerPID, MyName)

  after 3000 ->
    {error, timeout_after_3000_ms}

  end.

%%% @doc  Listens on Messages to start the Diffie-Hellman key
%%%       with the transferred MySecretKey and MyName
%%%       which shall be the name of the executing partner.
%%%       exchange by starting the following receive construct:
%%%       {startKeyExchange, PublicData}: 
%%%           The message including all information needed to 
%%%           start the key exchange by computing the own public 
%%%           data which will then be send to the PartnerPID as 
%%%           follows: {componentKey, MyPublicData}.
%%%           Afterwards, the private shared key will be printed 
%%%           out and the function calls a recursion.
%%%       terminante:        
%%%           Prints out that this function terminates with the 
%%%           executing PID and returns ok.
%%%       UnexpectedMessage:    
%%%           Prints out any unexpected incomping message and 
%%%           calls a recursion.
%%% @end
-spec listenKeyExchange(pos_integer(), string()) -> term().
listenKeyExchange(MySecretKey, MyName) ->
  receive

    {startKeyExchange, #publicData{p = P, g = G, componentKey = PartnerComponentKey, pid = PartnerPID, name = PartnerName}} ->
      MyComponentKey    = computeMyPublicComponentKey(P, G, MySecretKey),
      MyPublicData      = #publicData{p = P, g = G, componentKey = MyComponentKey, pid = self(), name = MyName},
      PartnerPID ! {componentKey, MyPublicData},
      PrivateSharedKey  = computeSharedPrivateKey(P, PartnerComponentKey, MySecretKey),
      printSharedPrivateKey(self(), MyName, PartnerName, PrivateSharedKey),
      listenKeyExchange(MySecretKey, MyName);

    terminate ->
      io:format("~p terminates!~n", [self()]),
      ok;

    UnexpectedMessage ->
      printUnexpectedMessage(UnexpectedMessage),
      listenKeyExchange(MySecretKey, MyName)

  end.

%%% @doc  Prints out the UnexpectedMessage as follows:
%%%       Received an unexpected message: 'Unexpected Message'
%%% @end
-spec printUnexpectedMessage(string()) -> term().
printUnexpectedMessage(UnexpectedMessage) ->
  io:format("Received an unexpected message: ~p~n", [UnexpectedMessage]).

%%% @doc  Prints out the shared private key as follows:
%%%       'MyName' ('PID'): The shared private Key,
%%%       exchanged with 'PartnerName' is: 'SharedKey'
%%% @end
-spec printSharedPrivateKey(term(), string(), string(), string()) -> term().
printSharedPrivateKey(PID, MyName, ParnterName, SharedKey) ->
  io:format("~p (~p): The shared private Key, exchanged with ~p is: ~p~n", [MyName, PID, ParnterName, SharedKey]).

%%% @doc  Starts a key exchange example by spawning the Alice 
%%%       process, which executes the listenKeyExchange function 
%%%       with MySecretKey = 15, and the Bob process, which 
%%%       exectues the startKeyExchange function with P = 23, 
%%%       G = 5, MySecretKey = 6 and PartnerPID = Alice. Returns
%%%       {Alice, Bob} (pids).
%%%
-spec startExample() -> term().
startExample() ->
  Alice   = spawn(diffie_hellman, listenKeyExchange, [15, "Alice"]),
  Bob     = spawn(diffie_hellman, startKeyExchange, [23, 5, 6, Alice, "Bob"]),
  {Alice, Bob}.

%%% @doc  Starts a key exchange remote example by spawning the 
%%%       Alice process, which executes the listenKeyExchange 
%%%       function with MySecretKey = 15, and the Bob process,
%%%       located on the RemoteNode, which exectues the 
%%%       startKeyExchange function with P = 23, G = 5, 
%%%       MySecretKey = 6 and Alice PID.
%%%       Returns the pids of Alice and Bob.
%%% @end
-spec startRemoteExample(atom()) -> term().
startRemoteExample(RemoteNode) ->
  Alice   = spawn(RemoteNode, diffie_hellman, listenKeyExchange, [15, "Alice"]),
  Bob     = spawn(diffie_hellman, startKeyExchange, [23, 5, 6, Alice, "Bob"]),
  {Alice, Bob}.

%%% @doc  Starts a key exchange remote example by spawning the 
%%%       Alice process, which executes the listenKeyExchange 
%%%       function with AliceSecretKey, and the Bob process,
%%%       located on the RemoteNode, which exectues the 
%%%       startKeyExchange function with P, G, 
%%%       BobSecretKey and Alice PID.
%%%       Returns the pids of Alice and Bob.
%%% @end
-spec startRemoteExample(atom(), pos_integer(), pos_integer(), pos_integer(), pos_integer()) -> term().
startRemoteExample(RemoteNode, P, G, BobSecretKey, AliceSecretKey) ->
  Alice   = spawn(RemoteNode, diffie_hellman, listenKeyExchange, [AliceSecretKey, "Alice"]),
  Bob     = spawn(diffie_hellman, startKeyExchange, [P, G, BobSecretKey, Alice, "Bob"]),
  {Alice, Bob}.
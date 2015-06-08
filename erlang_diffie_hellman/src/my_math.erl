%%% @author     Florian Willich
%%% @copyright  The MIT License (MIT) Copyright (c) 2014 
%%%             University of Applied Sciences, Berlin, Germany
%%%             Florian Willich
%%%             For more detailed information, please read the 
%%%             licence.txt in the erlang root directory.
%%% @doc        This is my math module for mathematical 
%%%             functions not provided by the erlang standard 
%%%             library.
%%% @end
%%% Created 2015-06-06

-module(my_math).
-author("Florian Willich").
-export([pow/2]).

%%% @doc  Returns the value of Base to the power of Exponent.
%%%       If Base and Exponent is 0 the function returns 
%%%       {error, undefined_arithmetic_expression},
%%%       The motivation to implement this function was that 
%%%       there is no erlang standard library pow function 
%%%       returning an integer.
%%% @end
-spec pow(integer(), integer()) -> number() | {error, atom()}.
pow(0, 0) ->
  {error, undefined_arithmetic_expression};

pow(Base, 0) ->
  case Base < 0 of
    true -> -1;
    false -> 1
  end;

pow(Base, Exponent) ->
  case Exponent < 0 of
    true -> 1 / pow(Base, -Exponent, 0);
    false -> pow(Base, Exponent, 0)
  end.

%%% @doc  Returns the value of Base to the power of Exponent. 
%%%       Acc should be 0 for initiating computation.
%%%       The motivation to implement this function was that 
%%%       there is no erlang standard library pow function 
%%%       returning an integer.
%%% @end
-spec pow(pos_integer(), non_neg_integer(), non_neg_integer()) -> integer().
pow(_, 0, Acc) -> Acc;

pow(Base, Exponent, 0) ->
  pow(Base, Exponent - 1, Base);

pow(Base, Exponent, Acc) ->
  pow(Base, Exponent - 1, Acc * Base).
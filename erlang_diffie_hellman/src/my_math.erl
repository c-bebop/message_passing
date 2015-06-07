%%% @author     Florian Willich
%%% @copyright  The MIT License (MIT) for more information see
%%%             http://opensource.org/licenses/MIT
%%% @doc        This is my math module for mathematical functions not provided
%%%             by the erlang standard library.
%%% @end
%%% Created 2015-06-06

-module(my_math).
-author("Florian Willich").
-export([pow/2]).

%%% Returns the value of Base to the power of Exponent.
%%% If Base and Exponent is 0 the function returns undefinedArithmeticExpression.
%%% The motivation to implement this function was that there is no erlang
%%% standard library pow function returning an integer.
-spec pow(integer(), integer()) -> number().
pow(0, 0) ->
  undefinedArithmeticExpression;

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

%%% Returns the value of Base to the power of Exponent. Acc should be 0 for
%%% initiating computation.
%%% If Base and Exponent is 0 the function returns undefinedArithmeticExpression.
%%% The motivation to implement this function was that there is no erlang
%%% standard library pow function returning an integer.
-spec pow(pos_integer(), non_neg_integer(), non_neg_integer()) -> integer().
pow(0, 0, _) ->
  undefinedArithmeticExpression;

pow(_, 0, Acc) -> Acc;

pow(Base, Exponent, 0) ->
  pow(Base, Exponent - 1, Base);

pow(Base, Exponent, Acc) ->
  pow(Base, Exponent - 1, Acc * Base).
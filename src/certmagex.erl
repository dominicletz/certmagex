-module(certmagex).
-include_lib("public_key/include/public_key.hrl"). 
-export([not_after/1]).

not_after(Certbin) ->
    #'Certificate'{tbsCertificate = #'TBSCertificate'{validity = #'Validity'{notAfter = NotAfter}}} = public_key:pkix_decode_cert(Certbin, plain),
    time_str_2_gregorian_sec(NotAfter).

time_str_2_gregorian_sec({utcTime, [Y1,Y2,M1,M2,D1,D2,H1,H2,M3,M4,S1,S2,Z]}) ->
    case list_to_integer([Y1,Y2]) of
	N when N >= 50 ->
	    time_str_2_gregorian_sec({generalTime, 
				      [$1,$9,Y1,Y2,M1,M2,D1,D2,
				       H1,H2,M3,M4,S1,S2,Z]});
	_ ->
	    time_str_2_gregorian_sec({generalTime, 
				      [$2,$0,Y1,Y2,M1,M2,D1,D2,
				       H1,H2,M3,M4,S1,S2,Z]}) 
    end;

time_str_2_gregorian_sec({_,[Y1,Y2,Y3,Y4,M1,M2,D1,D2,H1,H2,M3,M4,S1,S2,$Z]}) ->
    Year  = list_to_integer([Y1, Y2, Y3, Y4]),
    Month = list_to_integer([M1, M2]),
    Day   = list_to_integer([D1, D2]),
    Hour  = list_to_integer([H1, H2]),
    Min   = list_to_integer([M3, M4]),
    Sec   = list_to_integer([S1, S2]),
    calendar:datetime_to_gregorian_seconds({{Year, Month, Day},
					    {Hour, Min, Sec}}).

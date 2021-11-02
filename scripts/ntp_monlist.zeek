module NTP;

@load-plugin BR_UFRGS_INF::RNA
@load BR_UFRGS_INF/RNA/main

export {
	redef enum Notice::Type += {
		NTP_Monlist_Queries,
		};

	# The code value maps to the NTP mode type - for now I am mostly
	#  interested in control messages.
	#
	# Mode	Description
	# 0	reserved.
	# 1	Symmetric active.
	# 2	Symmetric passive.
	# 3	Client.
	# 4	Server.
	# 5	Broadcast.
	# 6	NTP control message.
	# 7	private use.
	const NTP_RESERVED = 0;
	const NTP_SYM_ACTIVE = 1;
	const NTP_SYM_PASSIVE = 2;
	const NTP_CLIENT = 3;
	const NTP_SERVER = 4;
	const NTP_BROADCAST = 5;
	const NTP_CONTROL = 6;
	const NTP_PRIVATE = 7;

	} # end export


event ntp_message(c: connection, is_orig: bool, msg: NTP::Message)
	{

	if ((msg$mode == NTP_PRIVATE) || (msg$mode == NTP_CONTROL)) {

		if ( ! Site::is_neighbor_addr(c$id$resp_h) && ! Site::is_local_addr(c$id$resp_h)) { # Note: "Everything" needs this information.

			# 1st approach: 
				# Rewrite Cordoni's logic:
					# Store the addresses of interest + timestamp.
					# Update the query/byte counts.
					# Upon attack detection, generate specific logs. 

			NOTICE([$note=NTP::NTP_Monlist_Queries,
				$conn=c,
				$suppress_for=0hrs,#6hrs,
				$msg=fmt("NTP monlist queries"),
				$identifier=cat(c$id$orig_h)]);
			}
		}
	}

# 2nd approach: 
	# Offload this processing to the DP. 

event rna_ntp_monlist(c: connection, is_orig: bool) # , msg: BR_UFRGS_INF::RNA::Message)
	{
		NOTICE([$note=RNA::NTP_Monlist_Detected, # fmt("BR_UFRGS_INF::RNA::NTP_Monlist_Detected"),
				$conn=c,
				$suppress_for=0hrs,
				$msg=fmt("RNA: NTP monlist detected!"),
				$identifier=cat(c$id$orig_h)]);
	}

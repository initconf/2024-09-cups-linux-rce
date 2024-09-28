hook Notice::policy(n: Notice::Info)
	{
	if ( n$note == CUPS::Callback )
		{
		add n$actions[Notice::ACTION_EMAIL];
		add n$actions[Notice::ACTION_DROP];
		#Notice::email_notice_to(n, "ir-reports@lbl.gov", T);
		}

	if ( n$note == CUPS::CallbackIP )
		{
		#add n$actions[Notice::ACTION_EMAIL];
		add n$actions[Notice::ACTION_DROP];
		#Notice::email_notice_to(n, "ir-reports@lbl.gov", T);
		}

	if ( n$note == CUPS::ScannerIP )
		{
		#add n$actions[Notice::ACTION_EMAIL];
		add n$actions[Notice::ACTION_DROP];
		#Notice::email_notice_to(n, "ir-reports@lbl.gov", T);
		}

	if ( n$note == CUPS::Probe )
		{
		#add n$actions[Notice::ACTION_EMAIL];
		add n$actions[Notice::ACTION_DROP];
		#Notice::email_notice_to(n, "ir-reports@lbl.gov", T);
		}
	}

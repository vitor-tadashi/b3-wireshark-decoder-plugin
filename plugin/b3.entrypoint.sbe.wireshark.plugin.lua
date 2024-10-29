-----------------------------------------------------------------------
-- Lua Script Wireshark Dissector - BETA version 0.4
-----------------------------------------------------------------------
-- Lua dissectors are an easily edited and modified cross platform dissection solution.
-- Feel free to modify. Enjoy.
-- Based on: https://github.com/Open-Markets-Initiative
-- Protocol:
--   Organization: B3 S.A. – Brasil, Bolsa, Balcão
--   Supported versions:
--     - 8.0.0
--     - 8.1.1
-----------------------------------------------------------------------
-- History
-- 2024/09/26:  Add support for schema 8.1.1 fields
-- 2024/09/26:  Wireshark is now able to identify messages from different versions of the protocol
-- 2024/03/12:  Fix outbound business header size
--              Add desk ID dissector
--              Add memo dissector
--              Add text dissector
-- 2024/03/11:  Add credentials dissector
--              Add client IP dissector
--              Add client app name dissector
--              Add client app version dissector
--              Add investor ID dissector
--              Fix padding
-- 2024/03/04:  MVP - only decoding fixed fields

-----------------------------------------------------------------------

-- B3 Equities BinaryEntryPoint Sbe 8.0 Protocol
local b3_entrypoint_sbe = Proto("b3.entrypoint.sbe", "B3 S.A. – Brasil, Bolsa, Balcão - Entrypoint SBE v8.1.1")

-- Component Tables
local show = {}
local format = {}
local b3_entrypoint_sbe_display = {}
local b3_entrypoint_sbe_dissect = {}
local b3_entrypoint_sbe_size_of = {}
local verify = {}
local translate = {}

-----------------------------------------------------------------------
-- Declare Protocol Fields
-----------------------------------------------------------------------
-- B3 Admin Messages

b3_entrypoint_sbe.fields.simple_open_frame = ProtoField.new("Simple Open Frame", "b3.entrypoint.sbe.simple_open_frame", ftypes.STRING)
b3_entrypoint_sbe.fields.simple_open_framing_header = ProtoField.new("SOFH (Simple Open Framing Header)", "b3", ftypes.STRING)
b3_entrypoint_sbe.fields.message_header = ProtoField.new("SBE (Simple Binary Entrypoint) Header", "b3.entrypoint.sbe.message_header", ftypes.STRING)
b3_entrypoint_sbe.fields.admin_message = ProtoField.new("Admin messages", "b3.entrypoint.sbe.admin", ftypes.STRING)
b3_entrypoint_sbe.fields.negotiate_message = ProtoField.new("Negotiate", "b3.entrypoint.sbe.admin.negotiate", ftypes.STRING)
b3_entrypoint_sbe.fields.negotiate_response_message = ProtoField.new("Negotiate Response", "b3.entrypoint.sbe.admin.negotiate_response", ftypes.STRING)
b3_entrypoint_sbe.fields.negotiate_reject_message = ProtoField.new("Negotiate Reject", "b3.entrypoint.sbe.admin.negotiate_reject", ftypes.STRING)
b3_entrypoint_sbe.fields.establish_message = ProtoField.new("Establish", "b3.entrypoint.sbe.admin.establish", ftypes.STRING)
b3_entrypoint_sbe.fields.establish_ack_message = ProtoField.new("Establish Ack", "b3.entrypoint.sbe.admin.establish_ack", ftypes.STRING)
b3_entrypoint_sbe.fields.establish_reject_message = ProtoField.new("Establish Reject", "b3.entrypoint.sbe.admin.establish_reject", ftypes.STRING)
b3_entrypoint_sbe.fields.sequence_message = ProtoField.new("Sequence", "b3.entrypoint.sbe.admin.sequence", ftypes.STRING)
b3_entrypoint_sbe.fields.not_applied_message = ProtoField.new("Not Applied", "b3.entrypoint.sbe.admin.not_applied", ftypes.STRING)
b3_entrypoint_sbe.fields.retransmit_reject_message = ProtoField.new("Retransmit Reject", "b3.entrypoint.sbe.admin.retransmit_reject", ftypes.STRING)
b3_entrypoint_sbe.fields.retransmission_message = ProtoField.new("Retransmission", "b3.entrypoint.sbe.admin.retransmission", ftypes.STRING)
b3_entrypoint_sbe.fields.terminate_message = ProtoField.new("Terminate", "b3.entrypoint.sbe.admin.terminate", ftypes.STRING)

-- B3 Inbound Messages
b3_entrypoint_sbe.fields.inbound_message = ProtoField.new("Inbound messages", "b3.entrypoint.sbe.in", ftypes.STRING)
b3_entrypoint_sbe.fields.simple_new_order_message = ProtoField.new("Simple New Order", "b3.entrypoint.sbe.in.simple_new_order", ftypes.STRING)
b3_entrypoint_sbe.fields.new_order_single_message = ProtoField.new("New Order Single", "b3.entrypoint.sbe.in.new_order_single", ftypes.STRING)
b3_entrypoint_sbe.fields.simple_modify_order_message = ProtoField.new("Simple Modify Order", "b3.entrypoint.sbe.in.simple_modify_order", ftypes.STRING)
b3_entrypoint_sbe.fields.order_cancel_replace_request_message = ProtoField.new("Order Cancel Replace Request", "b3.entrypoint.sbe.in.order_cancel_replace_request", ftypes.STRING)
b3_entrypoint_sbe.fields.order_cancel_request_message = ProtoField.new("Order Cancel Request", "b3.entrypoint.sbe.in.order_cancel_request", ftypes.STRING)
b3_entrypoint_sbe.fields.new_order_cross_message = ProtoField.new("New Order Cross", "b3.entrypoint.sbe.in.new_order_cross", ftypes.STRING)
b3_entrypoint_sbe.fields.order_mass_action_request_message = ProtoField.new("Order Mass Action Request", "b3.entrypoint.sbe.in.order_mass_action_request", ftypes.STRING)

-- B3 Outbound Messages
b3_entrypoint_sbe.fields.outbound_message = ProtoField.new("Outbound messages", "b3.entrypoint.sbe.out", ftypes.STRING)
b3_entrypoint_sbe.fields.execution_report_cancel_message = ProtoField.new("Execution Report Cancel", "b3.entrypoint.sbe.out.er_cancel", ftypes.STRING)
b3_entrypoint_sbe.fields.execution_report_forward_message = ProtoField.new("Execution Report forward", "b3.entrypoint.sbe.out.er_forward", ftypes.STRING)
b3_entrypoint_sbe.fields.execution_report_modify_message = ProtoField.new("Execution Report Modify", "b3.entrypoint.sbe.out.er_modify", ftypes.STRING)
b3_entrypoint_sbe.fields.execution_report_new_message = ProtoField.new("Execution Report New", "b3.entrypoint.sbe.out.er_new", ftypes.STRING)
b3_entrypoint_sbe.fields.execution_report_reject_message = ProtoField.new("Execution Report Reject", "b3.entrypoint.sbe.out.er_reject", ftypes.STRING)
b3_entrypoint_sbe.fields.execution_report_trade_message = ProtoField.new("Execution Report Trade", "b3.entrypoint.sbe.out.er_trade", ftypes.STRING)
b3_entrypoint_sbe.fields.business_message_reject = ProtoField.new("Business Message Reject", "b3.entrypoint.sbe.out.business_message_reject", ftypes.STRING)
b3_entrypoint_sbe.fields.order_mass_action_report_message = ProtoField.new("Order Mass Action Report", "b3.entrypoint.sbe.out.order_mass_action_report", ftypes.STRING)

-- B3 Equities BinaryEntryPoint Sbe 8.0 Fields
b3_entrypoint_sbe.fields.account = ProtoField.new("Account", "b3.entrypoint.sbe.account", ftypes.UINT32)
b3_entrypoint_sbe.fields.account_type = ProtoField.new("Account Type", "b3.entrypoint.sbe.account_type", ftypes.UINT8)
b3_entrypoint_sbe.fields.aggressor_indicator = ProtoField.new("Aggressor Indicator", "b3.entrypoint.sbe.aggressor_indicator", ftypes.UINT8)
b3_entrypoint_sbe.fields.alloc_account = ProtoField.new("Alloc Account", "b3.entrypoint.sbe.alloc_account", ftypes.UINT32)
b3_entrypoint_sbe.fields.alloc_id = ProtoField.new("Alloc ID", "b3.entrypoint.sbe.alloc_id", ftypes.UINT64)
b3_entrypoint_sbe.fields.alloc_no_orders_type = ProtoField.new("Alloc No Orders Type", "b3.entrypoint.sbe.alloc_no_orders_type", ftypes.STRING)
b3_entrypoint_sbe.fields.alloc_qty = ProtoField.new("Alloc Qty", "b3.entrypoint.sbe.alloc_qty", ftypes.UINT64)
b3_entrypoint_sbe.fields.alloc_rej_code = ProtoField.new("Alloc Rej Code", "b3.entrypoint.sbe.alloc_rej_code", ftypes.UINT32)
b3_entrypoint_sbe.fields.alloc_report_id = ProtoField.new("Alloc Report ID", "b3.entrypoint.sbe.alloc_report_id", ftypes.UINT64)
b3_entrypoint_sbe.fields.alloc_report_type = ProtoField.new("Alloc Report Type", "b3.entrypoint.sbe.alloc_report_type", ftypes.STRING)
b3_entrypoint_sbe.fields.alloc_status = ProtoField.new("Alloc Status", "b3.entrypoint.sbe.alloc_status", ftypes.STRING)
b3_entrypoint_sbe.fields.alloc_trans_type = ProtoField.new("Alloc Trans Type", "b3.entrypoint.sbe.alloc_trans_type", ftypes.STRING)
b3_entrypoint_sbe.fields.alloc_type = ProtoField.new("Alloc Type", "b3.entrypoint.sbe.alloc_type", ftypes.STRING)
b3_entrypoint_sbe.fields.allocation_instruction_message = ProtoField.new("Allocation Instruction", "b3.entrypoint.sbe.allocation_instruction_message", ftypes.STRING)
b3_entrypoint_sbe.fields.allocation_report_message = ProtoField.new("Allocation Report", "b3.entrypoint.sbe.allocation_report_message", ftypes.STRING)
b3_entrypoint_sbe.fields.asset = ProtoField.new("Asset", "b3.entrypoint.sbe.asset", ftypes.STRING)
b3_entrypoint_sbe.fields.bidirectional_business_header = ProtoField.new("Bidirectional Business Header", "b3.entrypoint.sbe.bidirectional_business_header", ftypes.STRING)
b3_entrypoint_sbe.fields.block_length = ProtoField.new("Block Length", "b3.entrypoint.sbe.block_length", ftypes.UINT16)

b3_entrypoint_sbe.fields.business_reject_reason = ProtoField.new("Business Reject Reason", "b3.entrypoint.sbe.business_reject_reason", ftypes.UINT32)
b3_entrypoint_sbe.fields.business_reject_ref_id = ProtoField.new("Business Reject Ref ID", "b3.entrypoint.sbe.business_reject_ref_id", ftypes.UINT64)
b3_entrypoint_sbe.fields.cancel_on_disconnect_type = ProtoField.new("Cancel On Disconnect Type", "b3.entrypoint.sbe.cancel_on_disconnect_type", ftypes.UINT8)
b3_entrypoint_sbe.fields.clearing_business_date = ProtoField.new("Clearing Business Date", "b3.entrypoint.sbe.clearing_business_date", ftypes.UINT16)
b3_entrypoint_sbe.fields.client_app_name = ProtoField.new("Client app name", "b3.entrypoint.sbe.client_app_name", ftypes.STRING)
b3_entrypoint_sbe.fields.client_app_version = ProtoField.new("Client app version", "b3.entrypoint.sbe.client_app_version", ftypes.STRING)
b3_entrypoint_sbe.fields.client_ip = ProtoField.new("Client IP", "b3.entrypoint.sbe.client_ip", ftypes.STRING)
b3_entrypoint_sbe.fields.clordid = ProtoField.new("ClOrdId", "b3.entrypoint.sbe.clordid", ftypes.UINT64)
b3_entrypoint_sbe.fields.clordid_optional = ProtoField.new("ClOrdId Optional", "b3.entrypoint.sbe.clordid_optional", ftypes.UINT64)
b3_entrypoint_sbe.fields.cod_timeout_window = ProtoField.new("COD Timeout Window", "b3.entrypoint.sbe.cod_timeout_window", ftypes.UINT64)
b3_entrypoint_sbe.fields.contra_broker = ProtoField.new("Contra Broker", "b3.entrypoint.sbe.contra_broker", ftypes.UINT32)
b3_entrypoint_sbe.fields.contrary_instruction_indicator = ProtoField.new("Contrary Instruction Indicator", "b3.entrypoint.sbe.contrary_instruction_indicator", ftypes.UINT8)
b3_entrypoint_sbe.fields.count = ProtoField.new("Count", "b3.entrypoint.sbe.count", ftypes.UINT32)
b3_entrypoint_sbe.fields.credentials = ProtoField.new("Credentials", "b3.entrypoint.sbe.credentials", ftypes.STRING)
b3_entrypoint_sbe.fields.crossed_indicator = ProtoField.new("Crossed Indicator", "b3.entrypoint.sbe.crossed_indicator", ftypes.UINT16)
b3_entrypoint_sbe.fields.crossid = ProtoField.new("CrossId", "b3.entrypoint.sbe.crossid", ftypes.UINT64)
b3_entrypoint_sbe.fields.crossid_optional = ProtoField.new("CrossId Optional", "b3.entrypoint.sbe.crossid_optional", ftypes.UINT64)
b3_entrypoint_sbe.fields.cum_qty = ProtoField.new("Cum Qty", "b3.entrypoint.sbe.cum_qty", ftypes.UINT64)
b3_entrypoint_sbe.fields.current_session_ver_id = ProtoField.new("Current Session Ver ID", "b3.entrypoint.sbe.current_session_ver_id", ftypes.UINT64)
b3_entrypoint_sbe.fields.custodian = ProtoField.new("Custodian", "b3.entrypoint.sbe.custodian", ftypes.UINT32)
b3_entrypoint_sbe.fields.custodian_info = ProtoField.new("Custodian Info", "b3.entrypoint.sbe.custodian_info", ftypes.STRING)
b3_entrypoint_sbe.fields.custody_account = ProtoField.new("Custody Account", "b3.entrypoint.sbe.custody_account", ftypes.UINT32)
b3_entrypoint_sbe.fields.custody_allocation_type = ProtoField.new("Custody Allocation Type", "b3.entrypoint.sbe.custody_allocation_type", ftypes.UINT32)
b3_entrypoint_sbe.fields.cxl_rej_response_to = ProtoField.new("Cxl Rej Response To", "b3.entrypoint.sbe.cxl_rej_response_to", ftypes.UINT8)
b3_entrypoint_sbe.fields.days_to_settlement = ProtoField.new("Days To Settlement", "b3.entrypoint.sbe.days_to_settlement", ftypes.UINT16)
b3_entrypoint_sbe.fields.days_to_settlement_optional = ProtoField.new("Days To Settlement Optional", "b3.entrypoint.sbe.days_to_settlement_optional", ftypes.UINT16)
b3_entrypoint_sbe.fields.desk_id = ProtoField.new("Desk ID", "b3.entrypoint.sbe.desk_id", ftypes.STRING)
b3_entrypoint_sbe.fields.document = ProtoField.new("Document", "b3.entrypoint.sbe.document", ftypes.UINT32)
b3_entrypoint_sbe.fields.encoding_type = ProtoField.new("Encoding Type", "b3.entrypoint.sbe.encoding_type", ftypes.UINT16)
b3_entrypoint_sbe.fields.entering_firm = ProtoField.new("Entering Firm", "b3.entrypoint.sbe.entering_firm", ftypes.UINT32)
b3_entrypoint_sbe.fields.entering_firm_optional = ProtoField.new("Entering Firm Optional", "b3.entrypoint.sbe.entering_firm_optional", ftypes.UINT32)
b3_entrypoint_sbe.fields.entering_trader = ProtoField.new("Entering Trader", "b3.entrypoint.sbe.entering_trader", ftypes.STRING)
b3_entrypoint_sbe.fields.executing_trader = ProtoField.new("Executing Trader", "b3.entrypoint.sbe.executing_trader", ftypes.STRING)
b3_entrypoint_sbe.fields.executing_trader_optional = ProtoField.new("Executing Trader Optional", "b3.entrypoint.sbe.executing_trader_optional", ftypes.STRING)
b3_entrypoint_sbe.fields.establishment_reject_code = ProtoField.new("Reject code", "b3.entrypoint.sbe.establishment_reject_code", ftypes.UINT8)
b3_entrypoint_sbe.fields.exec_id = ProtoField.new("Exec ID", "b3.entrypoint.sbe.exec_id", ftypes.UINT64)
b3_entrypoint_sbe.fields.exec_ref_id = ProtoField.new("Exec Ref ID", "b3.entrypoint.sbe.exec_ref_id", ftypes.UINT64)
b3_entrypoint_sbe.fields.exec_restatement_reason = ProtoField.new("Exec Restatement Reason", "b3.entrypoint.sbe.exec_restatement_reason", ftypes.UINT8)
b3_entrypoint_sbe.fields.exec_type = ProtoField.new("Exec Type", "b3.entrypoint.sbe.exec_type", ftypes.STRING)
b3_entrypoint_sbe.fields.execute_underlying_trade = ProtoField.new("Execute Underlying Trade", "b3.entrypoint.sbe.execute_underlying_trade", ftypes.STRING)

b3_entrypoint_sbe.fields.expire_date = ProtoField.new("Expire Date", "b3.entrypoint.sbe.expire_date", ftypes.UINT16)
b3_entrypoint_sbe.fields.fixed_rate = ProtoField.new("Fixed Rate", "b3.entrypoint.sbe.fixed_rate", ftypes.DOUBLE)
b3_entrypoint_sbe.fields.fixed_rate_optional = ProtoField.new("Fixed Rate Optional", "b3.entrypoint.sbe.fixed_rate_optional", ftypes.DOUBLE)
b3_entrypoint_sbe.fields.framing_header = ProtoField.new("Framing Header", "b3.entrypoint.sbe.framing_header", ftypes.STRING)
b3_entrypoint_sbe.fields.from_seq_no = ProtoField.new("From Seq No", "b3.entrypoint.sbe.from_seq_no", ftypes.UINT32)
b3_entrypoint_sbe.fields.group_size_encoding = ProtoField.new("Group Size Encoding", "b3.entrypoint.sbe.group_size_encoding", ftypes.STRING)
b3_entrypoint_sbe.fields.header_message = ProtoField.new("Header Message", "b3.entrypoint.sbe.header_message", ftypes.STRING)
b3_entrypoint_sbe.fields.inbound_business_header = ProtoField.new("Inbound Business Header", "b3.entrypoint.sbe.inbound_business_header", ftypes.STRING)
b3_entrypoint_sbe.fields.msg_seq_num = ProtoField.new("Msg Seq Num", "b3.entrypoint.sbe.msg_seq_num", ftypes.UINT32)
b3_entrypoint_sbe.fields.sending_time = ProtoField.new("Sending Time", "b3.entrypoint.sbe.sending_time", ftypes.UINT64)
b3_entrypoint_sbe.fields.received_time = ProtoField.new("Received Time", "b3.entrypoint.sbe.received_time", ftypes.UINT64)
b3_entrypoint_sbe.fields.strategy_id = ProtoField.new("Strategy ID", "b3.entrypoint.sbe.strategy_id", ftypes.UINT32)
b3_entrypoint_sbe.fields.action_requested_from_session_id = ProtoField.new("Cancel on behalf", "b3.entrypoint.sbe.action_requested_from_session_id", ftypes.UINT32)
b3_entrypoint_sbe.fields.market_segment_id = ProtoField.new("Market Segment ID", "b3.entrypoint.sbe.market_segment_id", ftypes.UINT8)
b3_entrypoint_sbe.fields.poss_resend = ProtoField.new("Possible Resend", "b3.entrypoint.sbe.poss_resend", ftypes.STRING)
b3_entrypoint_sbe.fields.individual_alloc_id = ProtoField.new("Individual Alloc ID", "b3.entrypoint.sbe.individual_alloc_id", ftypes.UINT64)
b3_entrypoint_sbe.fields.investor_id = ProtoField.new("Investor ID", "b3.entrypoint.sbe.investor_id", ftypes.STRING)
b3_entrypoint_sbe.fields.implied_event_id = ProtoField.new("Implied Event ID", "b3.entrypoint.sbe.implied_event_id", ftypes.STRING)
b3_entrypoint_sbe.fields.keep_alive_interval = ProtoField.new("Keep Alive Interval", "b3.entrypoint.sbe.keep_alive_interval", ftypes.UINT64)
b3_entrypoint_sbe.fields.last_incoming_seq_no = ProtoField.new("Last Incoming Seq No", "b3.entrypoint.sbe.last_incoming_seq_no", ftypes.UINT32)
b3_entrypoint_sbe.fields.last_incoming_seq_no_optional = ProtoField.new("Last Incoming Seq No Optional", "b3.entrypoint.sbe.last_incoming_seq_no_optional", ftypes.UINT32)
b3_entrypoint_sbe.fields.last_px = ProtoField.new("Last Px", "b3.entrypoint.sbe.last_px", ftypes.DOUBLE)
b3_entrypoint_sbe.fields.last_qty = ProtoField.new("Last Qty", "b3.entrypoint.sbe.last_qty", ftypes.UINT64)
b3_entrypoint_sbe.fields.leaves_qty = ProtoField.new("Leaves Qty", "b3.entrypoint.sbe.leaves_qty", ftypes.UINT64)
b3_entrypoint_sbe.fields.leg_ratio_qty = ProtoField.new("Leg Ratio Qty", "b3.entrypoint.sbe.leg_ratio_qty", ftypes.DOUBLE)
b3_entrypoint_sbe.fields.leg_security_exchange = ProtoField.new("Leg Security Exchange", "b3.entrypoint.sbe.leg_security_exchange", ftypes.STRING)
b3_entrypoint_sbe.fields.leg_side = ProtoField.new("Leg Side", "b3.entrypoint.sbe.leg_side", ftypes.STRING)
b3_entrypoint_sbe.fields.leg_symbol = ProtoField.new("Leg Symbol", "b3.entrypoint.sbe.leg_symbol", ftypes.STRING)
b3_entrypoint_sbe.fields.length = ProtoField.new("Length", "b3.entrypoint.sbe.length", ftypes.UINT8)
b3_entrypoint_sbe.fields.var_data_char = ProtoField.new("Variable Data", "b3.entrypoint.sbe.var_data_char", ftypes.STRING)
b3_entrypoint_sbe.fields.long_qty = ProtoField.new("Long Qty", "b3.entrypoint.sbe.long_qty", ftypes.UINT64)
b3_entrypoint_sbe.fields.long_qty_optional = ProtoField.new("Long Qty Optional", "b3.entrypoint.sbe.long_qty_optional", ftypes.UINT64)
b3_entrypoint_sbe.fields.market_segment_received_time = ProtoField.new("Market Segment Received Time", "b3.entrypoint.sbe.market_segment_received_time", ftypes.UINT64)
b3_entrypoint_sbe.fields.mass_action_reject_reason = ProtoField.new("Mass Action Reject Reason", "b3.entrypoint.sbe.mass_action_reject_reason", ftypes.UINT8)
b3_entrypoint_sbe.fields.mass_action_report_id = ProtoField.new("Mass Action Report ID", "b3.entrypoint.sbe.mass_action_report_id", ftypes.UINT64)

b3_entrypoint_sbe.fields.mass_action_report_id_optional = ProtoField.new("Mass Action Report ID Optional", "b3.entrypoint.sbe.mass_action_report_id_optional", ftypes.UINT64)
b3_entrypoint_sbe.fields.mass_action_response = ProtoField.new("Mass Action Response", "b3.entrypoint.sbe.mass_action_response", ftypes.STRING)
b3_entrypoint_sbe.fields.mass_action_scope = ProtoField.new("Mass Action Scope", "b3.entrypoint.sbe.mass_action_scope", ftypes.UINT8)
b3_entrypoint_sbe.fields.mass_action_type = ProtoField.new("Mass Action Type", "b3.entrypoint.sbe.mass_action_type", ftypes.UINT8)
b3_entrypoint_sbe.fields.mass_cancel_restatement_reason = ProtoField.new("Mass Cancel Restatement Reason", "b3.entrypoint.sbe.mass_cancel_restatement_reason", ftypes.UINT8)
b3_entrypoint_sbe.fields.max_floor = ProtoField.new("Max Floor", "b3.entrypoint.sbe.max_floor", ftypes.UINT64)
b3_entrypoint_sbe.fields.memo = ProtoField.new("Memo", "b3.entrypoint.sbe.memo", ftypes.STRING)

b3_entrypoint_sbe.fields.message_length = ProtoField.new("Message length", "b3.entrypoint.sbe.message_length", ftypes.UINT16)
b3_entrypoint_sbe.fields.min_qty = ProtoField.new("Min Qty", "b3.entrypoint.sbe.min_qty", ftypes.UINT64)
b3_entrypoint_sbe.fields.mm_protection_reset = ProtoField.new("Mm Protection Reset", "b3.entrypoint.sbe.mm_protection_reset", ftypes.UINT8)
b3_entrypoint_sbe.fields.multi_leg_reporting_type = ProtoField.new("Multi Leg Reporting Type", "b3.entrypoint.sbe.multi_leg_reporting_type", ftypes.STRING)

b3_entrypoint_sbe.fields.negotiation_reject_code = ProtoField.new("Negotiation reject code", "b3.entrypoint.sbe.negotiation_reject_code", ftypes.UINT8)

b3_entrypoint_sbe.fields.next_seq_no = ProtoField.new("Next Seq No", "b3.entrypoint.sbe.next_seq_no", ftypes.UINT32)
b3_entrypoint_sbe.fields.no_legs_group = ProtoField.new("No Legs Group", "b3.entrypoint.sbe.no_legs_group", ftypes.STRING)
b3_entrypoint_sbe.fields.no_legs_groups = ProtoField.new("No Legs Groups", "b3.entrypoint.sbe.no_legs_groups", ftypes.STRING)
b3_entrypoint_sbe.fields.no_positions_group = ProtoField.new("No Positions Group", "b3.entrypoint.sbe.no_positions_group", ftypes.STRING)
b3_entrypoint_sbe.fields.no_positions_groups = ProtoField.new("No Positions Groups", "b3.entrypoint.sbe.no_positions_groups", ftypes.STRING)
b3_entrypoint_sbe.fields.no_sides_group = ProtoField.new("No Sides Group", "b3.entrypoint.sbe.no_sides_group", ftypes.STRING)
b3_entrypoint_sbe.fields.no_sides_groups = ProtoField.new("No Sides Groups", "b3.entrypoint.sbe.no_sides_groups", ftypes.STRING)

b3_entrypoint_sbe.fields.num_in_group = ProtoField.new("Num In Group", "b3.entrypoint.sbe.num_in_group", ftypes.UINT8)
b3_entrypoint_sbe.fields.onbehalf_firm = ProtoField.new("Onbehalf Firm", "b3.entrypoint.sbe.onbehalf_firm", ftypes.UINT32)
b3_entrypoint_sbe.fields.ord_rej_reason = ProtoField.new("Ord Rej Reason", "b3.entrypoint.sbe.ord_rej_reason", ftypes.UINT32)
b3_entrypoint_sbe.fields.ord_status = ProtoField.new("Ord Status", "b3.entrypoint.sbe.ord_status", ftypes.STRING)
b3_entrypoint_sbe.fields.ord_tag_id = ProtoField.new("Ord Tag ID", "b3.entrypoint.sbe.ord_tag_id", ftypes.UINT8)

b3_entrypoint_sbe.fields.order_category = ProtoField.new("Order Category", "b3.entrypoint.sbe.order_category", ftypes.STRING)
b3_entrypoint_sbe.fields.order_id = ProtoField.new("Order ID", "b3.entrypoint.sbe.order_id", ftypes.UINT64)
b3_entrypoint_sbe.fields.order_id_optional = ProtoField.new("Order ID Optional", "b3.entrypoint.sbe.order_id_optional", ftypes.UINT64)

b3_entrypoint_sbe.fields.order_qty = ProtoField.new("Order Qty", "b3.entrypoint.sbe.order_qty", ftypes.UINT64)
b3_entrypoint_sbe.fields.order_qty_optional = ProtoField.new("Order Qty Optional", "b3.entrypoint.sbe.order_qty_optional", ftypes.UINT64)
b3_entrypoint_sbe.fields.ordtype = ProtoField.new("OrdType", "b3.entrypoint.sbe.ordtype", ftypes.STRING)
b3_entrypoint_sbe.fields.orig_pos_req_ref_id = ProtoField.new("Orig Pos Req Ref ID", "b3.entrypoint.sbe.orig_pos_req_ref_id", ftypes.UINT64)
b3_entrypoint_sbe.fields.origclordid = ProtoField.new("OrigClOrdId", "b3.entrypoint.sbe.origclordid", ftypes.UINT64)
b3_entrypoint_sbe.fields.outbound_business_header = ProtoField.new("Outbound Business Header", "b3.entrypoint.sbe.outbound_business_header", ftypes.STRING)
b3_entrypoint_sbe.fields.packet = ProtoField.new("Packet", "b3.entrypoint.sbe.packet", ftypes.STRING)
b3_entrypoint_sbe.fields.payload = ProtoField.new("Payload", "b3.entrypoint.sbe.payload", ftypes.STRING)
b3_entrypoint_sbe.fields.pos_maint_action = ProtoField.new("Pos Maint Action", "b3.entrypoint.sbe.pos_maint_action", ftypes.STRING)
b3_entrypoint_sbe.fields.pos_maint_result = ProtoField.new("Pos Maint Result", "b3.entrypoint.sbe.pos_maint_result", ftypes.UINT32)
b3_entrypoint_sbe.fields.pos_maint_rpt_id = ProtoField.new("Pos Maint Rpt ID", "b3.entrypoint.sbe.pos_maint_rpt_id", ftypes.UINT64)
b3_entrypoint_sbe.fields.pos_maint_rpt_ref_id = ProtoField.new("Pos Maint Rpt Ref ID", "b3.entrypoint.sbe.pos_maint_rpt_ref_id", ftypes.UINT64)
b3_entrypoint_sbe.fields.pos_maint_status = ProtoField.new("Pos Maint Status", "b3.entrypoint.sbe.pos_maint_status", ftypes.STRING)
b3_entrypoint_sbe.fields.pos_req_id = ProtoField.new("Pos Req ID", "b3.entrypoint.sbe.pos_req_id", ftypes.UINT64)
b3_entrypoint_sbe.fields.pos_req_id_optional = ProtoField.new("Pos Req ID Optional", "b3.entrypoint.sbe.pos_req_id_optional", ftypes.UINT64)
b3_entrypoint_sbe.fields.pos_trans_type = ProtoField.new("Pos Trans Type", "b3.entrypoint.sbe.pos_trans_type", ftypes.UINT8)
b3_entrypoint_sbe.fields.pos_type = ProtoField.new("Pos Type", "b3.entrypoint.sbe.pos_type", ftypes.STRING)
b3_entrypoint_sbe.fields.cross_type = ProtoField.new("Cross Type", "b3.entrypoint.sbe.cross_type", ftypes.UINT8)
b3_entrypoint_sbe.fields.cross_prioritization = ProtoField.new("Cross Prioritization", "b3.entrypoint.sbe.cross_prioritization", ftypes.UINT8)
b3_entrypoint_sbe.fields.prefix = ProtoField.new("Prefix", "b3.entrypoint.sbe.prefix", ftypes.UINT16)
b3_entrypoint_sbe.fields.price = ProtoField.new("Price", "b3.entrypoint.sbe.price", ftypes.DOUBLE)
b3_entrypoint_sbe.fields.price_optional = ProtoField.new("Price Optional", "b3.entrypoint.sbe.price_optional", ftypes.DOUBLE)
b3_entrypoint_sbe.fields.protection_price = ProtoField.new("Protection Price", "b3.entrypoint.sbe.protection_price", ftypes.DOUBLE)
b3_entrypoint_sbe.fields.quantity = ProtoField.new("Quantity", "b3.entrypoint.sbe.quantity", ftypes.UINT64)
b3_entrypoint_sbe.fields.max_sweep_qty = ProtoField.new("Max Sweep Quantity", "b3.entrypoint.sbe.max_sweep_qty", ftypes.UINT64)
b3_entrypoint_sbe.fields.quote_cancel_message = ProtoField.new("Quote Cancel", "b3.entrypoint.sbe.quote_cancel_message", ftypes.STRING)
b3_entrypoint_sbe.fields.quote_id = ProtoField.new("Quote ID", "b3.entrypoint.sbe.quote_id", ftypes.UINT64)
b3_entrypoint_sbe.fields.quote_id_optional = ProtoField.new("Quote ID Optional", "b3.entrypoint.sbe.quote_id_optional", ftypes.UINT64)
b3_entrypoint_sbe.fields.quote_message = ProtoField.new("Quote", "b3.entrypoint.sbe.quote_message", ftypes.STRING)
b3_entrypoint_sbe.fields.quote_reject_reason = ProtoField.new("Quote Reject Reason", "b3.entrypoint.sbe.quote_reject_reason", ftypes.UINT32)
b3_entrypoint_sbe.fields.quote_req_id = ProtoField.new("Quote Req ID", "b3.entrypoint.sbe.quote_req_id", ftypes.STRING)
b3_entrypoint_sbe.fields.quote_request_message = ProtoField.new("Quote Request", "b3.entrypoint.sbe.quote_request_message", ftypes.STRING)
b3_entrypoint_sbe.fields.quote_request_reject_message = ProtoField.new("Quote Request Reject", "b3.entrypoint.sbe.quote_request_reject_message", ftypes.STRING)
b3_entrypoint_sbe.fields.quote_request_reject_reason = ProtoField.new("Quote Request Reject Reason", "b3.entrypoint.sbe.quote_request_reject_reason", ftypes.UINT32)
b3_entrypoint_sbe.fields.quote_status = ProtoField.new("Quote Status", "b3.entrypoint.sbe.quote_status", ftypes.UINT8)
b3_entrypoint_sbe.fields.quote_status_report_message = ProtoField.new("Quote Status Report", "b3.entrypoint.sbe.quote_status_report_message", ftypes.STRING)
b3_entrypoint_sbe.fields.quote_status_response_to = ProtoField.new("Quote Status Response To", "b3.entrypoint.sbe.quote_status_response_to", ftypes.STRING)
b3_entrypoint_sbe.fields.ref_msg_type = ProtoField.new("Ref Msg Type", "b3.entrypoint.sbe.ref_msg_type", ftypes.UINT8)
b3_entrypoint_sbe.fields.ref_seq_num = ProtoField.new("Ref Seq Num", "b3.entrypoint.sbe.ref_seq_num", ftypes.UINT32)
b3_entrypoint_sbe.fields.request_timestamp = ProtoField.new("Request Timestamp", "b3.entrypoint.sbe.request_timestamp", ftypes.UINT64)

b3_entrypoint_sbe.fields.retransmit_request_message = ProtoField.new("Retransmit Request", "b3.entrypoint.sbe.admin.retransmit_request", ftypes.STRING)
b3_entrypoint_sbe.fields.routing_instruction = ProtoField.new("Routing Instruction", "b3.entrypoint.sbe.routing_instruction", ftypes.UINT8)
b3_entrypoint_sbe.fields.schema_id = ProtoField.new("Schema ID", "b3.entrypoint.sbe.schema_id", ftypes.UINT16)
b3_entrypoint_sbe.fields.secondary_exec_id = ProtoField.new("Secondary Exec ID", "b3.entrypoint.sbe.secondary_exec_id", ftypes.UINT64)
b3_entrypoint_sbe.fields.secondary_order_id = ProtoField.new("Secondary Order ID", "b3.entrypoint.sbe.secondary_order_id", ftypes.UINT64)
b3_entrypoint_sbe.fields.secondary_order_id_optional = ProtoField.new("Secondary Order ID Optional", "b3.entrypoint.sbe.secondary_order_id_optional", ftypes.UINT64)
b3_entrypoint_sbe.fields.security_definition_request_message = ProtoField.new("Security Definition Request", "b3.entrypoint.sbe.security_definition_request_message", ftypes.STRING)
b3_entrypoint_sbe.fields.security_definition_response_message = ProtoField.new("Security Definition Response", "b3.entrypoint.sbe.security_definition_response_message", ftypes.STRING)
b3_entrypoint_sbe.fields.security_exchange = ProtoField.new("Security Exchange", "b3.entrypoint.sbe.security_exchange", ftypes.STRING)
b3_entrypoint_sbe.fields.security_id_source = ProtoField.new("Security ID Source", "b3.entrypoint.sbe.security_id_source", ftypes.UINT8)
b3_entrypoint_sbe.fields.security_id = ProtoField.new("Security ID", "b3.entrypoint.sbe.security_id", ftypes.UINT64)
b3_entrypoint_sbe.fields.security_id_optional = ProtoField.new("Security ID Optional", "b3.entrypoint.sbe.security_id_optional", ftypes.UINT64)
b3_entrypoint_sbe.fields.security_req_id = ProtoField.new("Security Req ID", "b3.entrypoint.sbe.security_req_id", ftypes.UINT64)
b3_entrypoint_sbe.fields.security_response_id = ProtoField.new("Security Response ID", "b3.entrypoint.sbe.security_response_id", ftypes.UINT64)
b3_entrypoint_sbe.fields.security_response_type = ProtoField.new("Security Response Type", "b3.entrypoint.sbe.security_response_type", ftypes.UINT8)
b3_entrypoint_sbe.fields.security_strategy_type = ProtoField.new("Security Strategy Type", "b3.entrypoint.sbe.security_strategy_type", ftypes.STRING)
b3_entrypoint_sbe.fields.self_trade_prevention_instruction = ProtoField.new("Self Trade Prevention Instruction", "b3.entrypoint.sbe.self_trade_prevention_instruction", ftypes.UINT8)
b3_entrypoint_sbe.fields.sender_location = ProtoField.new("Sender Location", "b3.entrypoint.sbe.sender_location", ftypes.STRING)
b3_entrypoint_sbe.fields.retransmit_reject_code = ProtoField.new("Retransmit reject code", "b3.entrypoint.sbe.retransmit_reject_code", ftypes.UINT8)
b3_entrypoint_sbe.fields.session_id = ProtoField.new("Session ID", "b3.entrypoint.sbe.session_id", ftypes.UINT32)
b3_entrypoint_sbe.fields.session_ver_id = ProtoField.new("Session Ver ID", "b3.entrypoint.sbe.session_ver_id", ftypes.UINT64)
b3_entrypoint_sbe.fields.settltype = ProtoField.new("SettlType", "b3.entrypoint.sbe.settltype", ftypes.STRING)
b3_entrypoint_sbe.fields.settltype_optional = ProtoField.new("SettlType Optional", "b3.entrypoint.sbe.settltype_optional", ftypes.STRING)
b3_entrypoint_sbe.fields.short_qty = ProtoField.new("Short Qty", "b3.entrypoint.sbe.short_qty", ftypes.UINT64)
b3_entrypoint_sbe.fields.side = ProtoField.new("Side", "b3.entrypoint.sbe.side", ftypes.STRING)

b3_entrypoint_sbe.fields.simple_ordtype = ProtoField.new("Simple OrdType", "b3.entrypoint.sbe.simple_ordtype", ftypes.STRING)
b3_entrypoint_sbe.fields.single_cancel_restatement_reason = ProtoField.new("Single Cancel Restatement Reason", "b3.entrypoint.sbe.single_cancel_restatement_reason", ftypes.UINT8)
b3_entrypoint_sbe.fields.stop_px = ProtoField.new("Stop Px", "b3.entrypoint.sbe.stop_px", ftypes.DOUBLE)
b3_entrypoint_sbe.fields.symbol = ProtoField.new("Symbol", "b3.entrypoint.sbe.symbol", ftypes.STRING)
b3_entrypoint_sbe.fields.template_id = ProtoField.new("Template ID", "b3.entrypoint.sbe.template_id", ftypes.UINT16)

b3_entrypoint_sbe.fields.termination_code = ProtoField.new("Termination Code", "b3.entrypoint.sbe.termination_code", ftypes.UINT8)
b3_entrypoint_sbe.fields.text = ProtoField.new("Text", "b3.entrypoint.sbe.text", ftypes.STRING)
b3_entrypoint_sbe.fields.threshold_amount = ProtoField.new("Threshold Amount", "b3.entrypoint.sbe.threshold_amount", ftypes.DOUBLE)
b3_entrypoint_sbe.fields.time_in_force = ProtoField.new("Time In Force", "b3.entrypoint.sbe.time_in_force", ftypes.STRING)
b3_entrypoint_sbe.fields.time_in_force_optional = ProtoField.new("Time In Force Optional", "b3.entrypoint.sbe.time_in_force_optional", ftypes.STRING)
b3_entrypoint_sbe.fields.time_in_force_simple = ProtoField.new("Time In Force Simple", "b3.entrypoint.sbe.time_in_force_simple", ftypes.STRING)
b3_entrypoint_sbe.fields.timestamp = ProtoField.new("Timestamp", "b3.entrypoint.sbe.timestamp", ftypes.UINT64)
b3_entrypoint_sbe.fields.tot_no_related_sym = ProtoField.new("Tot No Related Sym", "b3.entrypoint.sbe.tot_no_related_sym", ftypes.UINT8)
b3_entrypoint_sbe.fields.trade_date = ProtoField.new("Trade Date", "b3.entrypoint.sbe.trade_date", ftypes.UINT16)
b3_entrypoint_sbe.fields.trade_date_optional = ProtoField.new("Trade Date Optional", "b3.entrypoint.sbe.trade_date_optional", ftypes.UINT16)
b3_entrypoint_sbe.fields.trade_id = ProtoField.new("Trade ID", "b3.entrypoint.sbe.trade_id", ftypes.UINT32)
b3_entrypoint_sbe.fields.trade_id_optional = ProtoField.new("Trade ID Optional", "b3.entrypoint.sbe.trade_id_optional", ftypes.UINT32)
b3_entrypoint_sbe.fields.event_id = ProtoField.new("Event ID", "b3.entrypoint.sbe.event_id", ftypes.UINT32)
b3_entrypoint_sbe.fields.no_related_trades = ProtoField.new("Related trades", "b3.entrypoint.sbe.no_related_trades", ftypes.UINT16)
b3_entrypoint_sbe.fields.transact_time = ProtoField.new("Transact Time", "b3.entrypoint.sbe.transact_time", ftypes.UINT64)
b3_entrypoint_sbe.fields.var_data = ProtoField.new("Var Data", "b3.entrypoint.sbe.var_data", ftypes.BYTES)
b3_entrypoint_sbe.fields.version = ProtoField.new("Version", "b3.entrypoint.sbe.version", ftypes.UINT16)
b3_entrypoint_sbe.fields.working_indicator = ProtoField.new("Working Indicator", "b3.entrypoint.sbe.working_indicator", ftypes.UINT8)

b3_entrypoint_sbe.fields.trading_session_id = ProtoField.new("Trading Session ID", "b3.entrypoint.sbe.trading_session_id", ftypes.UINT8)
b3_entrypoint_sbe.fields.trading_session_sub_id = ProtoField.new("Trading Session Sub ID", "b3.entrypoint.sbe.trading_session_sub_id", ftypes.UINT8)
b3_entrypoint_sbe.fields.security_trading_status = ProtoField.new("Security Trading Status", "b3.entrypoint.sbe.security_trading_status", ftypes.UINT8)
-----------------------------------------------------------------------
-- Declare Dissection Options
-----------------------------------------------------------------------

-- B3 Equities BinaryEntryPoint Sbe 8.0 Element Dissection Options
show.allocation_instruction_message = true
show.allocation_report_message = true
show.business_message_reject = true
show.client_app_name = true
show.client_app_version = true
show.client_ip = true
show.credentials = true
show.custodian_info = true
show.desk_id = true
show.establish_ack_message = true
show.establish_message = true
show.establish_reject_message = true
show.execution_report_cancel_message = true
show.execution_report_forward_message = true
show.execution_report_modify_message = true
show.execution_report_new_message = true
show.execution_report_reject_message = true
show.execution_report_trade_message = true
show.framing_header = true
show.group_size_encoding = true
show.header_message = true
show.investor_id = true
show.memo = true
show.message_header = true
show.negotiate_message = true
show.negotiate_reject_message = true
show.negotiate_response_message = true
show.new_order_cross_message = true
show.new_order_single_message = true
show.no_legs_group = true
show.no_legs_groups = true
show.no_positions_group = true
show.no_positions_groups = true
show.no_sides_group = true
show.no_sides_groups = true
show.not_applied_message = true
show.order_cancel_replace_request_message = true
show.order_cancel_request_message = true
show.order_mass_action_report_message = true
show.order_mass_action_request_message = true
show.packet = true
show.position_maintenance_cancel_request_message = true
show.position_maintenance_report_message = true
show.position_maintenance_request_message = true
show.quote_cancel_message = true
show.quote_message = true
show.quote_req_id = true
show.quote_request_message = true
show.quote_request_reject_message = true
show.quote_status_report_message = true
show.retransmission_message = true
show.retransmit_reject_message = true
show.retransmit_request_message = true
show.security_definition_request_message = true
show.security_definition_response_message = true
show.sequence_message = true
show.simple_modify_order_message = true
show.simple_new_order_message = true
show.simple_open_frame = true
show.simple_open_framing_header = true
show.terminate_message = true
show.text = true
show.payload = false

-- Register B3 Equities BinaryEntryPoint Sbe 8.0 Show Options
b3_entrypoint_sbe.prefs.show_allocation_instruction_message = Pref.bool("Show Allocation Instruction Message", show.allocation_instruction_message, "Parse and add Allocation Instruction Message to protocol tree")
b3_entrypoint_sbe.prefs.show_allocation_report_message = Pref.bool("Show Allocation Report Message", show.allocation_report_message, "Parse and add Allocation Report Message to protocol tree")
b3_entrypoint_sbe.prefs.show_business_message_reject = Pref.bool("Show Business Message Reject", show.business_message_reject, "Parse and add Business Message Reject to protocol tree")
b3_entrypoint_sbe.prefs.show_client_app_name = Pref.bool("Show Client App Name", show.client_app_name, "Parse and add Client App Name to protocol tree")
b3_entrypoint_sbe.prefs.show_client_app_version = Pref.bool("Show Client App Version", show.client_app_version, "Parse and add Client App Version to protocol tree")
b3_entrypoint_sbe.prefs.show_client_ip = Pref.bool("Show Client Ip", show.client_ip, "Parse and add Client Ip to protocol tree")
b3_entrypoint_sbe.prefs.show_credentials = Pref.bool("Show Credentials", show.credentials, "Parse and add Credentials to protocol tree")
b3_entrypoint_sbe.prefs.show_custodian_info = Pref.bool("Show Custodian Info", show.custodian_info, "Parse and add Custodian Info to protocol tree")
b3_entrypoint_sbe.prefs.show_desk_id = Pref.bool("Show Desk ID", show.desk_id, "Parse and add Desk ID to protocol tree")
b3_entrypoint_sbe.prefs.show_establish_ack_message = Pref.bool("Show Establish Ack Message", show.establish_ack_message, "Parse and add Establish Ack Message to protocol tree")
b3_entrypoint_sbe.prefs.show_establish_message = Pref.bool("Show Establish Message", show.establish_message, "Parse and add Establish Message to protocol tree")
b3_entrypoint_sbe.prefs.show_establish_reject_message = Pref.bool("Show Establish Reject Message", show.establish_reject_message, "Parse and add Establish Reject Message to protocol tree")
b3_entrypoint_sbe.prefs.show_execution_report_cancel_message = Pref.bool("Show Execution Report Cancel Message", show.execution_report_cancel_message, "Parse and add Execution Report Cancel Message to protocol tree")
b3_entrypoint_sbe.prefs.show_execution_report_forward_message = Pref.bool("Show Execution Report Forward Message", show.execution_report_forward_message, "Parse and add Execution Report Forward Message to protocol tree")
b3_entrypoint_sbe.prefs.show_execution_report_modify_message = Pref.bool("Show Execution Report Modify Message", show.execution_report_modify_message, "Parse and add Execution Report Modify Message to protocol tree")
b3_entrypoint_sbe.prefs.show_execution_report_new_message = Pref.bool("Show Execution Report New Message", show.execution_report_new_message, "Parse and add Execution Report New Message to protocol tree")
b3_entrypoint_sbe.prefs.show_execution_report_reject_message = Pref.bool("Show Execution Report Reject Message", show.execution_report_reject_message, "Parse and add Execution Report Reject Message to protocol tree")
b3_entrypoint_sbe.prefs.show_execution_report_trade_message = Pref.bool("Show Execution Report Trade Message", show.execution_report_trade_message, "Parse and add Execution Report Trade Message to protocol tree")
b3_entrypoint_sbe.prefs.show_framing_header = Pref.bool("Show Framing Header", show.framing_header, "Parse and add Framing Header to protocol tree")
b3_entrypoint_sbe.prefs.show_group_size_encoding = Pref.bool("Show Group Size Encoding", show.group_size_encoding, "Parse and add Group Size Encoding to protocol tree")
b3_entrypoint_sbe.prefs.show_header_message = Pref.bool("Show Header Message", show.header_message, "Parse and add Header Message to protocol tree")
b3_entrypoint_sbe.prefs.show_investor_id = Pref.bool("Show Investor ID", show.investor_id, "Parse and add Investor ID to protocol tree")
b3_entrypoint_sbe.prefs.show_memo = Pref.bool("Show Memo", show.memo, "Parse and add Memo to protocol tree")
b3_entrypoint_sbe.prefs.show_message_header = Pref.bool("Show Message Header", show.message_header, "Parse and add Message Header to protocol tree")
b3_entrypoint_sbe.prefs.show_negotiate_message = Pref.bool("Show Negotiate Message", show.negotiate_message, "Parse and add Negotiate Message to protocol tree")
b3_entrypoint_sbe.prefs.show_negotiate_reject_message = Pref.bool("Show Negotiate Reject Message", show.negotiate_reject_message, "Parse and add Negotiate Reject Message to protocol tree")
b3_entrypoint_sbe.prefs.show_negotiate_response_message = Pref.bool("Show Negotiate Response Message", show.negotiate_response_message, "Parse and add Negotiate Response Message to protocol tree")
b3_entrypoint_sbe.prefs.show_new_order_cross_message = Pref.bool("Show New Order Cross Message", show.new_order_cross_message, "Parse and add New Order Cross Message to protocol tree")
b3_entrypoint_sbe.prefs.show_new_order_single_message = Pref.bool("Show New Order Single Message", show.new_order_single_message, "Parse and add New Order Single Message to protocol tree")
b3_entrypoint_sbe.prefs.show_no_legs_group = Pref.bool("Show No Legs Group", show.no_legs_group, "Parse and add No Legs Group to protocol tree")
b3_entrypoint_sbe.prefs.show_no_legs_groups = Pref.bool("Show No Legs Groups", show.no_legs_groups, "Parse and add No Legs Groups to protocol tree")
b3_entrypoint_sbe.prefs.show_no_positions_group = Pref.bool("Show No Positions Group", show.no_positions_group, "Parse and add No Positions Group to protocol tree")
b3_entrypoint_sbe.prefs.show_no_positions_groups = Pref.bool("Show No Positions Groups", show.no_positions_groups, "Parse and add No Positions Groups to protocol tree")
b3_entrypoint_sbe.prefs.show_no_sides_group = Pref.bool("Show No Sides Group", show.no_sides_group, "Parse and add No Sides Group to protocol tree")
b3_entrypoint_sbe.prefs.show_no_sides_groups = Pref.bool("Show No Sides Groups", show.no_sides_groups, "Parse and add No Sides Groups to protocol tree")
b3_entrypoint_sbe.prefs.show_not_applied_message = Pref.bool("Show Not Applied Message", show.not_applied_message, "Parse and add Not Applied Message to protocol tree")
b3_entrypoint_sbe.prefs.show_order_cancel_replace_request_message = Pref.bool("Show Order Cancel Replace Request Message", show.order_cancel_replace_request_message, "Parse and add Order Cancel Replace Request Message to protocol tree")
b3_entrypoint_sbe.prefs.show_order_cancel_request_message = Pref.bool("Show Order Cancel Request Message", show.order_cancel_request_message, "Parse and add Order Cancel Request Message to protocol tree")
b3_entrypoint_sbe.prefs.show_order_mass_action_report_message = Pref.bool("Show Order Mass Action Report Message", show.order_mass_action_report_message, "Parse and add Order Mass Action Report Message to protocol tree")
b3_entrypoint_sbe.prefs.show_order_mass_action_request_message = Pref.bool("Show Order Mass Action Request Message", show.order_mass_action_request_message, "Parse and add Order Mass Action Request Message to protocol tree")
b3_entrypoint_sbe.prefs.show_packet = Pref.bool("Show Packet", show.packet, "Parse and add Packet to protocol tree")
b3_entrypoint_sbe.prefs.show_position_maintenance_cancel_request_message = Pref.bool("Show Position Maintenance Cancel Request Message", show.position_maintenance_cancel_request_message, "Parse and add Position Maintenance Cancel Request Message to protocol tree")
b3_entrypoint_sbe.prefs.show_position_maintenance_report_message = Pref.bool("Show Position Maintenance Report Message", show.position_maintenance_report_message, "Parse and add Position Maintenance Report Message to protocol tree")
b3_entrypoint_sbe.prefs.show_position_maintenance_request_message = Pref.bool("Show Position Maintenance Request Message", show.position_maintenance_request_message, "Parse and add Position Maintenance Request Message to protocol tree")
b3_entrypoint_sbe.prefs.show_quote_cancel_message = Pref.bool("Show Quote Cancel Message", show.quote_cancel_message, "Parse and add Quote Cancel Message to protocol tree")
b3_entrypoint_sbe.prefs.show_quote_message = Pref.bool("Show Quote Message", show.quote_message, "Parse and add Quote Message to protocol tree")
b3_entrypoint_sbe.prefs.show_quote_req_id = Pref.bool("Show Quote Req ID", show.quote_req_id, "Parse and add Quote Req ID to protocol tree")
b3_entrypoint_sbe.prefs.show_quote_request_message = Pref.bool("Show Quote Request Message", show.quote_request_message, "Parse and add Quote Request Message to protocol tree")
b3_entrypoint_sbe.prefs.show_quote_request_reject_message = Pref.bool("Show Quote Request Reject Message", show.quote_request_reject_message, "Parse and add Quote Request Reject Message to protocol tree")
b3_entrypoint_sbe.prefs.show_quote_status_report_message = Pref.bool("Show Quote Status Report Message", show.quote_status_report_message, "Parse and add Quote Status Report Message to protocol tree")
b3_entrypoint_sbe.prefs.show_retransmission_message = Pref.bool("Show Retransmission Message", show.retransmission_message, "Parse and add Retransmission Message to protocol tree")
b3_entrypoint_sbe.prefs.show_retransmit_reject_message = Pref.bool("Show Retransmit Reject Message", show.retransmit_reject_message, "Parse and add Retransmit Reject Message to protocol tree")
b3_entrypoint_sbe.prefs.show_retransmit_request_message = Pref.bool("Show Retransmit Request Message", show.retransmit_request_message, "Parse and add Retransmit Request Message to protocol tree")
b3_entrypoint_sbe.prefs.show_security_definition_request_message = Pref.bool("Show Security Definition Request Message", show.security_definition_request_message, "Parse and add Security Definition Request Message to protocol tree")
b3_entrypoint_sbe.prefs.show_security_definition_response_message = Pref.bool("Show Security Definition Response Message", show.security_definition_response_message, "Parse and add Security Definition Response Message to protocol tree")
b3_entrypoint_sbe.prefs.show_sequence_message = Pref.bool("Show Sequence Message", show.sequence_message, "Parse and add Sequence Message to protocol tree")
b3_entrypoint_sbe.prefs.show_simple_modify_order_message = Pref.bool("Show Simple Modify Order Message", show.simple_modify_order_message, "Parse and add Simple Modify Order Message to protocol tree")
b3_entrypoint_sbe.prefs.show_simple_new_order_message = Pref.bool("Show Simple New Order Message", show.simple_new_order_message, "Parse and add Simple New Order Message to protocol tree")
b3_entrypoint_sbe.prefs.show_simple_open_frame = Pref.bool("Show Simple Open Frame", show.simple_open_frame, "Parse and add Simple Open Frame to protocol tree")
b3_entrypoint_sbe.prefs.show_simple_open_framing_header = Pref.bool("Show Simple Open Framing Header", show.simple_open_framing_header, "Parse and add Simple Open Framing Header to protocol tree")
b3_entrypoint_sbe.prefs.show_terminate_message = Pref.bool("Show Terminate Message", show.terminate_message, "Parse and add Terminate Message to protocol tree")
b3_entrypoint_sbe.prefs.show_text = Pref.bool("Show Text", show.text, "Parse and add Text to protocol tree")
b3_entrypoint_sbe.prefs.show_payload = Pref.bool("Show Payload", show.payload, "Parse and add Payload to protocol tree")

-- Handle changed preferences
function b3_entrypoint_sbe.prefs_changed()
  local changed = false

  -- Check if show options have changed
  if show.allocation_instruction_message ~= b3_entrypoint_sbe.prefs.show_allocation_instruction_message then
    show.allocation_instruction_message = b3_entrypoint_sbe.prefs.show_allocation_instruction_message
    changed = true
  end
  if show.allocation_report_message ~= b3_entrypoint_sbe.prefs.show_allocation_report_message then
    show.allocation_report_message = b3_entrypoint_sbe.prefs.show_allocation_report_message
    changed = true
  end
  if show.business_message_reject ~= b3_entrypoint_sbe.prefs.show_business_message_reject then
    show.business_message_reject = b3_entrypoint_sbe.prefs.show_business_message_reject
    changed = true
  end
  if show.client_app_name ~= b3_entrypoint_sbe.prefs.show_client_app_name then
    show.client_app_name = b3_entrypoint_sbe.prefs.show_client_app_name
    changed = true
  end
  if show.client_app_version ~= b3_entrypoint_sbe.prefs.show_client_app_version then
    show.client_app_version = b3_entrypoint_sbe.prefs.show_client_app_version
    changed = true
  end
  if show.client_ip ~= b3_entrypoint_sbe.prefs.show_client_ip then
    show.client_ip = b3_entrypoint_sbe.prefs.show_client_ip
    changed = true
  end
  if show.credentials ~= b3_entrypoint_sbe.prefs.show_credentials then
    show.credentials = b3_entrypoint_sbe.prefs.show_credentials
    changed = true
  end
  if show.custodian_info ~= b3_entrypoint_sbe.prefs.show_custodian_info then
    show.custodian_info = b3_entrypoint_sbe.prefs.show_custodian_info
    changed = true
  end
  if show.desk_id ~= b3_entrypoint_sbe.prefs.show_desk_id then
    show.desk_id = b3_entrypoint_sbe.prefs.show_desk_id
    changed = true
  end
  if show.establish_ack_message ~= b3_entrypoint_sbe.prefs.show_establish_ack_message then
    show.establish_ack_message = b3_entrypoint_sbe.prefs.show_establish_ack_message
    changed = true
  end
  if show.establish_message ~= b3_entrypoint_sbe.prefs.show_establish_message then
    show.establish_message = b3_entrypoint_sbe.prefs.show_establish_message
    changed = true
  end
  if show.establish_reject_message ~= b3_entrypoint_sbe.prefs.show_establish_reject_message then
    show.establish_reject_message = b3_entrypoint_sbe.prefs.show_establish_reject_message
    changed = true
  end
  if show.execution_report_cancel_message ~= b3_entrypoint_sbe.prefs.show_execution_report_cancel_message then
    show.execution_report_cancel_message = b3_entrypoint_sbe.prefs.show_execution_report_cancel_message
    changed = true
  end
  if show.execution_report_forward_message ~= b3_entrypoint_sbe.prefs.show_execution_report_forward_message then
    show.execution_report_forward_message = b3_entrypoint_sbe.prefs.show_execution_report_forward_message
    changed = true
  end
  if show.execution_report_modify_message ~= b3_entrypoint_sbe.prefs.show_execution_report_modify_message then
    show.execution_report_modify_message = b3_entrypoint_sbe.prefs.show_execution_report_modify_message
    changed = true
  end
  if show.execution_report_new_message ~= b3_entrypoint_sbe.prefs.show_execution_report_new_message then
    show.execution_report_new_message = b3_entrypoint_sbe.prefs.show_execution_report_new_message
    changed = true
  end
  if show.execution_report_reject_message ~= b3_entrypoint_sbe.prefs.show_execution_report_reject_message then
    show.execution_report_reject_message = b3_entrypoint_sbe.prefs.show_execution_report_reject_message
    changed = true
  end
  if show.execution_report_trade_message ~= b3_entrypoint_sbe.prefs.show_execution_report_trade_message then
    show.execution_report_trade_message = b3_entrypoint_sbe.prefs.show_execution_report_trade_message
    changed = true
  end
  if show.framing_header ~= b3_entrypoint_sbe.prefs.show_framing_header then
    show.framing_header = b3_entrypoint_sbe.prefs.show_framing_header
    changed = true
  end
  if show.group_size_encoding ~= b3_entrypoint_sbe.prefs.show_group_size_encoding then
    show.group_size_encoding = b3_entrypoint_sbe.prefs.show_group_size_encoding
    changed = true
  end
  if show.header_message ~= b3_entrypoint_sbe.prefs.show_header_message then
    show.header_message = b3_entrypoint_sbe.prefs.show_header_message
    changed = true
  end
  if show.investor_id ~= b3_entrypoint_sbe.prefs.show_investor_id then
    show.investor_id = b3_entrypoint_sbe.prefs.show_investor_id
    changed = true
  end
  if show.memo ~= b3_entrypoint_sbe.prefs.show_memo then
    show.memo = b3_entrypoint_sbe.prefs.show_memo
    changed = true
  end
  if show.message_header ~= b3_entrypoint_sbe.prefs.show_message_header then
    show.message_header = b3_entrypoint_sbe.prefs.show_message_header
    changed = true
  end
  if show.negotiate_message ~= b3_entrypoint_sbe.prefs.show_negotiate_message then
    show.negotiate_message = b3_entrypoint_sbe.prefs.show_negotiate_message
    changed = true
  end
  if show.negotiate_reject_message ~= b3_entrypoint_sbe.prefs.show_negotiate_reject_message then
    show.negotiate_reject_message = b3_entrypoint_sbe.prefs.show_negotiate_reject_message
    changed = true
  end
  if show.negotiate_response_message ~= b3_entrypoint_sbe.prefs.show_negotiate_response_message then
    show.negotiate_response_message = b3_entrypoint_sbe.prefs.show_negotiate_response_message
    changed = true
  end
  if show.new_order_cross_message ~= b3_entrypoint_sbe.prefs.show_new_order_cross_message then
    show.new_order_cross_message = b3_entrypoint_sbe.prefs.show_new_order_cross_message
    changed = true
  end
  if show.new_order_single_message ~= b3_entrypoint_sbe.prefs.show_new_order_single_message then
    show.new_order_single_message = b3_entrypoint_sbe.prefs.show_new_order_single_message
    changed = true
  end
  if show.no_legs_group ~= b3_entrypoint_sbe.prefs.show_no_legs_group then
    show.no_legs_group = b3_entrypoint_sbe.prefs.show_no_legs_group
    changed = true
  end
  if show.no_legs_groups ~= b3_entrypoint_sbe.prefs.show_no_legs_groups then
    show.no_legs_groups = b3_entrypoint_sbe.prefs.show_no_legs_groups
    changed = true
  end
  if show.no_positions_group ~= b3_entrypoint_sbe.prefs.show_no_positions_group then
    show.no_positions_group = b3_entrypoint_sbe.prefs.show_no_positions_group
    changed = true
  end
  if show.no_positions_groups ~= b3_entrypoint_sbe.prefs.show_no_positions_groups then
    show.no_positions_groups = b3_entrypoint_sbe.prefs.show_no_positions_groups
    changed = true
  end
  if show.no_sides_group ~= b3_entrypoint_sbe.prefs.show_no_sides_group then
    show.no_sides_group = b3_entrypoint_sbe.prefs.show_no_sides_group
    changed = true
  end
  if show.no_sides_groups ~= b3_entrypoint_sbe.prefs.show_no_sides_groups then
    show.no_sides_groups = b3_entrypoint_sbe.prefs.show_no_sides_groups
    changed = true
  end
  if show.not_applied_message ~= b3_entrypoint_sbe.prefs.show_not_applied_message then
    show.not_applied_message = b3_entrypoint_sbe.prefs.show_not_applied_message
    changed = true
  end
  if show.order_cancel_replace_request_message ~= b3_entrypoint_sbe.prefs.show_order_cancel_replace_request_message then
    show.order_cancel_replace_request_message = b3_entrypoint_sbe.prefs.show_order_cancel_replace_request_message
    changed = true
  end
  if show.order_cancel_request_message ~= b3_entrypoint_sbe.prefs.show_order_cancel_request_message then
    show.order_cancel_request_message = b3_entrypoint_sbe.prefs.show_order_cancel_request_message
    changed = true
  end
  if show.order_mass_action_report_message ~= b3_entrypoint_sbe.prefs.show_order_mass_action_report_message then
    show.order_mass_action_report_message = b3_entrypoint_sbe.prefs.show_order_mass_action_report_message
    changed = true
  end
  if show.order_mass_action_request_message ~= b3_entrypoint_sbe.prefs.show_order_mass_action_request_message then
    show.order_mass_action_request_message = b3_entrypoint_sbe.prefs.show_order_mass_action_request_message
    changed = true
  end
  if show.packet ~= b3_entrypoint_sbe.prefs.show_packet then
    show.packet = b3_entrypoint_sbe.prefs.show_packet
    changed = true
  end
  if show.position_maintenance_cancel_request_message ~= b3_entrypoint_sbe.prefs.show_position_maintenance_cancel_request_message then
    show.position_maintenance_cancel_request_message = b3_entrypoint_sbe.prefs.show_position_maintenance_cancel_request_message
    changed = true
  end
  if show.position_maintenance_report_message ~= b3_entrypoint_sbe.prefs.show_position_maintenance_report_message then
    show.position_maintenance_report_message = b3_entrypoint_sbe.prefs.show_position_maintenance_report_message
    changed = true
  end
  if show.position_maintenance_request_message ~= b3_entrypoint_sbe.prefs.show_position_maintenance_request_message then
    show.position_maintenance_request_message = b3_entrypoint_sbe.prefs.show_position_maintenance_request_message
    changed = true
  end
  if show.quote_cancel_message ~= b3_entrypoint_sbe.prefs.show_quote_cancel_message then
    show.quote_cancel_message = b3_entrypoint_sbe.prefs.show_quote_cancel_message
    changed = true
  end
  if show.quote_message ~= b3_entrypoint_sbe.prefs.show_quote_message then
    show.quote_message = b3_entrypoint_sbe.prefs.show_quote_message
    changed = true
  end
  if show.quote_req_id ~= b3_entrypoint_sbe.prefs.show_quote_req_id then
    show.quote_req_id = b3_entrypoint_sbe.prefs.show_quote_req_id
    changed = true
  end
  if show.quote_request_message ~= b3_entrypoint_sbe.prefs.show_quote_request_message then
    show.quote_request_message = b3_entrypoint_sbe.prefs.show_quote_request_message
    changed = true
  end
  if show.quote_request_reject_message ~= b3_entrypoint_sbe.prefs.show_quote_request_reject_message then
    show.quote_request_reject_message = b3_entrypoint_sbe.prefs.show_quote_request_reject_message
    changed = true
  end
  if show.quote_status_report_message ~= b3_entrypoint_sbe.prefs.show_quote_status_report_message then
    show.quote_status_report_message = b3_entrypoint_sbe.prefs.show_quote_status_report_message
    changed = true
  end
  if show.retransmission_message ~= b3_entrypoint_sbe.prefs.show_retransmission_message then
    show.retransmission_message = b3_entrypoint_sbe.prefs.show_retransmission_message
    changed = true
  end
  if show.retransmit_reject_message ~= b3_entrypoint_sbe.prefs.show_retransmit_reject_message then
    show.retransmit_reject_message = b3_entrypoint_sbe.prefs.show_retransmit_reject_message
    changed = true
  end
  if show.retransmit_request_message ~= b3_entrypoint_sbe.prefs.show_retransmit_request_message then
    show.retransmit_request_message = b3_entrypoint_sbe.prefs.show_retransmit_request_message
    changed = true
  end
  if show.security_definition_request_message ~= b3_entrypoint_sbe.prefs.show_security_definition_request_message then
    show.security_definition_request_message = b3_entrypoint_sbe.prefs.show_security_definition_request_message
    changed = true
  end
  if show.security_definition_response_message ~= b3_entrypoint_sbe.prefs.show_security_definition_response_message then
    show.security_definition_response_message = b3_entrypoint_sbe.prefs.show_security_definition_response_message
    changed = true
  end
  if show.sequence_message ~= b3_entrypoint_sbe.prefs.show_sequence_message then
    show.sequence_message = b3_entrypoint_sbe.prefs.show_sequence_message
    changed = true
  end
  if show.simple_modify_order_message ~= b3_entrypoint_sbe.prefs.show_simple_modify_order_message then
    show.simple_modify_order_message = b3_entrypoint_sbe.prefs.show_simple_modify_order_message
    changed = true
  end
  if show.simple_new_order_message ~= b3_entrypoint_sbe.prefs.show_simple_new_order_message then
    show.simple_new_order_message = b3_entrypoint_sbe.prefs.show_simple_new_order_message
    changed = true
  end
  if show.simple_open_frame ~= b3_entrypoint_sbe.prefs.show_simple_open_frame then
    show.simple_open_frame = b3_entrypoint_sbe.prefs.show_simple_open_frame
    changed = true
  end
  if show.simple_open_framing_header ~= b3_entrypoint_sbe.prefs.show_simple_open_framing_header then
    show.simple_open_framing_header = b3_entrypoint_sbe.prefs.show_simple_open_framing_header
    changed = true
  end
  if show.terminate_message ~= b3_entrypoint_sbe.prefs.show_terminate_message then
    show.terminate_message = b3_entrypoint_sbe.prefs.show_terminate_message
    changed = true
  end
  if show.text ~= b3_entrypoint_sbe.prefs.show_text then
    show.text = b3_entrypoint_sbe.prefs.show_text
    changed = true
  end
  if show.payload ~= b3_entrypoint_sbe.prefs.show_payload then
    show.payload = b3_entrypoint_sbe.prefs.show_payload
    changed = true
  end

  -- Reload on changed preference
  if changed then
    reload()
  end
end


-----------------------------------------------------------------------
-- Dissect B3 Equities BinaryEntryPoint Sbe 8.0
-----------------------------------------------------------------------

-- Size: Encoding Type
b3_entrypoint_sbe_size_of.encoding_type = 2

-- Display: Encoding Type
b3_entrypoint_sbe_display.encoding_type = function(value, hex)
  if raw == Int64(0xEB50, 0xEB50) then
    return "Encoding type: INVALID ("..value..")"
  end

  return "Encoding type: "..value.." - HEX ("..hex..")"
end

-- Dissect: Encoding Type
b3_entrypoint_sbe_dissect.encoding_type = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.encoding_type
  local range = buffer(offset, length)
  local value = range:le_uint()
  local hex = range:bytes():tohex(false, " ")
  local display = b3_entrypoint_sbe_display.encoding_type(value, hex, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.encoding_type, range, value, display)

  return offset + length, value
end

-- Size: Message Length
b3_entrypoint_sbe_size_of.message_length = 2

-- Display: Message Length
b3_entrypoint_sbe_display.message_length = function(value)
  return "Message length: "..value
end

-- Dissect: Message Length
b3_entrypoint_sbe_dissect.message_length = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.message_length
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.message_length(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.message_length, range, value, display)

  return offset + length, value
end

-- Calculate size of: Framing Header
b3_entrypoint_sbe_size_of.framing_header = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.message_length

  index = index + b3_entrypoint_sbe_size_of.encoding_type

  return index
end

-- Display: Framing Header
b3_entrypoint_sbe_display.framing_header = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Framing Header
b3_entrypoint_sbe_dissect.framing_header_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Message Length: 2 Byte Unsigned Fixed Width Integer
  index, message_length = b3_entrypoint_sbe_dissect.message_length(buffer, index, packet, parent)

  -- Encoding Type: 2 Byte Unsigned Fixed Width Integer
  index, encoding_type = b3_entrypoint_sbe_dissect.encoding_type(buffer, index, packet, parent)

  return index
end

-- Dissect: Framing Header
b3_entrypoint_sbe_dissect.framing_header = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.framing_header then
    local length = b3_entrypoint_sbe_size_of.framing_header(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.framing_header(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.framing_header, range, display)
  end

  return b3_entrypoint_sbe_dissect.framing_header_fields(buffer, offset, packet, parent)
end

-- Calculate size of: Header Message
b3_entrypoint_sbe_size_of.header_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.framing_header(buffer, offset + index)

  return index
end

-- Display: Header Message
b3_entrypoint_sbe_display.header_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Header Message
b3_entrypoint_sbe_dissect.header_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Framing Header: Struct of 2 fields
  index, framing_header = b3_entrypoint_sbe_dissect.framing_header(buffer, index, packet, parent)

  return index
end

-- Dissect: Header Message
b3_entrypoint_sbe_dissect.header_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.header_message then
    local length = b3_entrypoint_sbe_size_of.header_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.header_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.header_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.header_message_fields(buffer, offset, packet, parent)
end

-- Size: Length
b3_entrypoint_sbe_size_of.length = 1

-- Display: Length
b3_entrypoint_sbe_display.length = function(value)
  return "Length: "..value
end

-- Dissect: Length
b3_entrypoint_sbe_dissect.length = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.length
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.length(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.length, range, value, display)

  return offset + length, value
end

-- Calculate size of: Text
b3_entrypoint_sbe_size_of.text = function(buffer, offset)
  return b3_entrypoint_sbe_size_of.variable_data(buffer, offset)
end

-- Display: Text
b3_entrypoint_sbe_display.text = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Text
b3_entrypoint_sbe_dissect.text_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Length: 1 Byte Unsigned Fixed Width Integer
  index, length = b3_entrypoint_sbe_dissect.length(buffer, index, packet, parent)

  -- Var Data char
  index, var_data_char = b3_entrypoint_sbe_dissect.var_data_char(buffer, index, packet, parent, length)

  return index
end

-- Dissect: Text
b3_entrypoint_sbe_dissect.text = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.text then
    local length = b3_entrypoint_sbe_size_of.text(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.text(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.text, range, display)
  end

  return b3_entrypoint_sbe_dissect.text_fields(buffer, offset, packet, parent)
end

-- Size: Document
b3_entrypoint_sbe_size_of.document = 4

-- Display: Document
b3_entrypoint_sbe_display.document = function(value)
  if self_trade_prevention_instruction == nil then
    return "Document: "..value
  end

  if self_trade_prevention_instruction > 0 and value == 0 then
    return "Document: INVALID("..value..") (required when self-trade prevention is not none)"
  end

  if prefix >= 100 and prefix <= 199 and value > 99999999 then
    return "Document: INVALID("..value..") (not a valid value for non registered resident this prefix range, should be between 0 and 99999999"
  end

  if prefix >= 200 and prefix <= 299 and value > 999999999 then
    return "Document: INVALID("..value..") (not a valid value for non registered resident this prefix range, should be between 0 and 999999999"
  end

  if prefix >= 300 and prefix <= 499 and value > 999999 then
    return "Document: INVALID("..value..") (not a valid value for non registered resident this prefix range, should be between 0 and 999999"
  end

  if value < 0 or value > 999999999 then
    return "Document: INVALID("..value..") (not a valid value, should be between 0 and 999999999"
  end

  return "Document: "..value
end

-- Dissect: Document
b3_entrypoint_sbe_dissect.document = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.document
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.document(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.document, range, value, display)

  return offset + length, value
end

-- Size: Prefix
b3_entrypoint_sbe_size_of.prefix = 2

-- Display: Prefix
b3_entrypoint_sbe_display.prefix = function(value)
  if self_trade_prevention_instruction == nil then
    return "Prefix: "..value
  end

  if self_trade_prevention_instruction > 0 and value == 0 then
    return "Prefix: INVALID("..value..") (required when self-trade prevention is not none)"
  end

  if value < 100 or value > 899 then
    return "Prefix: INVALID("..value..") (not a valid value, should be between 100 and 899"
  end

  return "Prefix: "..value
end

-- Dissect: Prefix
b3_entrypoint_sbe_dissect.prefix = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.prefix
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.prefix(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.prefix, range, value, display)

  return offset + length, value
end

-- Calculate size of: Investor ID
b3_entrypoint_sbe_size_of.investor_id = 8

-- Display: Investor ID
b3_entrypoint_sbe_display.investor_id = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Investor ID
b3_entrypoint_sbe_dissect.investor_id_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Prefix: 2 Byte Unsigned Fixed Width Integer
  index, prefix = b3_entrypoint_sbe_dissect.prefix(buffer, index, packet, parent)

  -- Padding
  index = index + 2

  -- Document: 4 Byte Unsigned Fixed Width Integer
  index, document = b3_entrypoint_sbe_dissect.document(buffer, index, packet, parent)

  return index
end

-- Dissect: Investor ID
b3_entrypoint_sbe_dissect.investor_id = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.investor_id then
    local length = b3_entrypoint_sbe_size_of.investor_id
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.investor_id(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.investor_id, range, display)
  end

  return b3_entrypoint_sbe_dissect.investor_id_fields(buffer, offset, packet, parent)
end

-- Calculate size of: Implied Event ID
b3_entrypoint_sbe_size_of.implied_event_id = 6

-- Display: Implied Event ID
b3_entrypoint_sbe_display.implied_event_id = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Investor ID
b3_entrypoint_sbe_dissect.implied_event_id_fields = function(buffer, offset, packet, parent)
  local index = offset

  index, event_id = b3_entrypoint_sbe_dissect.event_id(buffer, index, packet, parent)
  index, no_related_trades = b3_entrypoint_sbe_dissect.no_related_trades(buffer, index, packet, parent)

  return index
end

-- Dissect: Investor ID
b3_entrypoint_sbe_dissect.implied_event_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.implied_event_id
  local range = buffer(offset, length)
  local display = b3_entrypoint_sbe_display.implied_event_id(buffer, packet, parent)
  parent = parent:add(b3_entrypoint_sbe.fields.implied_event_id, range, display)

  return b3_entrypoint_sbe_dissect.implied_event_id_fields(buffer, offset, packet, parent)
end

-- Size: Security ID Source
b3_entrypoint_sbe_size_of.security_id_source = 1

-- Display: Ord Tag ID
b3_entrypoint_sbe_display.security_id_source = function(value)
  if value == 52 then
    return "Security ID source: ISIN"
  end

  if value == 56 then
    return "Security ID source: EXCHANGE_SYMBOL"
  end

  return "Security ID source: "..value
end

-- Dissect: Ord Tag ID
b3_entrypoint_sbe_dissect.security_id_source = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.security_id_source
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.security_id_source(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.security_id_source, range, value, display)

  return offset + length, value
end

-- Size: Security Exchange
b3_entrypoint_sbe_size_of.security_exchange = 4

-- Display: Security Exchange
b3_entrypoint_sbe_display.security_exchange = function(value)
  -- Check if field has value
  if value == nil or value == '' then
    return "Security exchange: NULL"
  end

  return "Security exchange: "..value
end

-- Dissect: Security Exchange
b3_entrypoint_sbe_dissect.security_exchange = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.security_exchange
  local range = buffer(offset, length)

  -- parse last octet
  local last = buffer(offset + length - 1, 1):uint()

  -- read full string or up to first zero
  local value = ''
  if last == 0 then
    value = range:stringz()
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.security_exchange(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.security_exchange, range, value, display)

  return offset + length, value
end

-- Size: Security ID Optional
b3_entrypoint_sbe_size_of.security_id_optional = 8

-- Display: Security ID Optional
b3_entrypoint_sbe_display.security_id_optional = function(value)
  return "Security ID: "..value
end

-- Dissect: Security ID Optional
b3_entrypoint_sbe_dissect.security_id_optional = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.security_id_optional
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.security_id_optional(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.security_id_optional, range, value, display)

  return offset + length, value
end

-- Size: Asset
b3_entrypoint_sbe_size_of.asset = 6

-- Display: Asset
b3_entrypoint_sbe_display.asset = function(value)
  -- Check if field has value
  if value == nil or value == '' then
    return "Asset: NULL"
  end

  return "Asset: "..value
end

-- Dissect: Asset
b3_entrypoint_sbe_dissect.asset = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.asset
  local range = buffer(offset, length)

  -- parse last octet
  local last = buffer(offset + length - 1, 1):uint()

  -- read full string or up to first zero
  local value = ''
  if last == 0 then
    value = range:stringz()
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.asset(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.asset, range, value, display)

  return offset + length, value
end

-- Dissect: Asset
b3_entrypoint_sbe_dissect.var_data_char = function(buffer, offset, packet, parent, length)
  if length == 0 then
    return  offset + length, ""
  end

  local range = buffer(offset, length)

  -- parse last octet
  local last = buffer(offset + length - 1, 1):uint()

  -- read full string or up to first zero
  local value = ''
  if last == 0 then
    value = range:stringz()
  else
    value = range:string()
  end

  parent:add(b3_entrypoint_sbe.fields.var_data_char, range, value, "Value: "..value)

  return offset + length, value
end

-- Dissect: Side Optional
b3_entrypoint_sbe_dissect.side_optional = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.side
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()
  local display = b3_entrypoint_sbe_display.side(value, true, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.side, range, value, display)

  return offset + length, value
end

-- Size: Ord Tag ID
b3_entrypoint_sbe_size_of.ord_tag_id = 1

-- Display: Ord Tag ID
b3_entrypoint_sbe_display.ord_tag_id = function(value)
  return "Order Tag ID: "..value
end

-- Dissect: Ord Tag ID
b3_entrypoint_sbe_dissect.ord_tag_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.ord_tag_id
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.ord_tag_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.ord_tag_id, range, value, display)

  return offset + length, value
end

-- Size: Mass Cancel Restatement Reason
b3_entrypoint_sbe_size_of.mass_cancel_restatement_reason = 1

-- Display: Mass Cancel Restatement Reason
b3_entrypoint_sbe_display.mass_cancel_restatement_reason = function(value)
  if value == 8 then
    return "Exec restatement reason: MARKET_OPTION (NOT VALID FOR ORDER MASS ACTION REQUEST)"
  end
  if value == 100 then
    return "Exec restatement reason: CANCEL_ON_HARD_DISCONNECTION (NOT VALID FOR ORDER MASS ACTION REQUEST)"
  end
  if value == 101 then
    return "Exec restatement reason: CANCEL_ON_TERMINATE (NOT VALID FOR ORDER MASS ACTION REQUEST)"
  end
  if value == 102 then
    return "Exec restatement reason: CANCEL_ON_DISCONNECT_AND_TERMINATE (NOT VALID FOR ORDER MASS ACTION REQUEST)"
  end
  if value == 103 then
    return "Exec restatement reason: SELF_TRADING_PREVENTION (NOT VALID FOR ORDER MASS ACTION REQUEST)"
  end
  if value == 105 then
    return "Exec restatement reason: CANCEL_FROM_FIRMSOFT (NOT VALID FOR ORDER MASS ACTION REQUEST)"
  end
  if value == 107 then
    return "Exec restatement reason: CANCEL_RESTING_ORDER_ON_SELF_TRADE (NOT VALID FOR ORDER MASS ACTION REQUEST)"
  end
  if value == 200 then
    return "Exec restatement reason: MARKET_MAKER_PROTECTION (NOT VALID FOR ORDER MASS ACTION REQUEST)"
  end
  if value == 201 then
    return "Exec restatement reason: RISK_MANAGEMENT_CANCELLATION (NOT VALID FOR ORDER MASS ACTION REQUEST)"
  end
  if value == 202 then
    return "Exec restatement reason: ORDER_MASS_ACTION_FROM_CLIENT_REQUEST"
  end
  if value == 203 then
    return "Exec restatement reason: CANCEL_ORDER_DUE_TO_OPERATIONAL_ERROR (NOT VALID FOR ORDER MASS ACTION REQUEST)"
  end
  if value == 204 then
    return "Exec restatement reason: ORDER_CANCELLED_DUE_TO_OPERATIONAL_ERROR (NOT VALID FOR ORDER MASS ACTION REQUEST)"
  end
  if value == 205 then
    return "Exec restatement reason: CANCEL_ORDER_FIRMSOFT_DUE_TO_OPERATIONAL_ERROR (NOT VALID FOR ORDER MASS ACTION REQUEST)"
  end
  if value == 206 then
    return "Exec restatement reason: ORDER_CANCELLED_FIRMSOFT_DUE_TO_OPERATIONAL_ERROR (NOT VALID FOR ORDER MASS ACTION REQUEST)"
  end
  if value == 207 then
    return "Exec restatement reason: MASS_CANCEL_ORDER_DUE_TO_OPERATIONAL_ERROR_REQUEST"
  end
  if value == 208 then
    return "Exec restatement reason: MASS_CANCEL_ORDER_DUE_TO_OPERATIONAL_ERROR_EFFECTIVE (NOT VALID FOR ORDER MASS ACTION REQUEST)"
  end
  if value == 209 then
    return "Exec restatement reason: CANCEL_ON_MIDPOINT_BROKER_ONLY_REMOVAL (NOT VALID FOR ORDER MASS ACTION REQUEST)"
  end
  if value == 210 then
    return "Exec restatement reason: CANCEL_REMAINING_FROM_SWEEP_CROSS (NOT VALID FOR ORDER MASS ACTION REQUEST)"
  end
  if value == 211 then
    return "Exec restatement reason: MASS_CANCEL_ON_BEHALF (NOT VALID FOR ORDER MASS ACTION REQUEST)"
  end
  if value == 212 then
    return "Exec restatement reason: MASS_CANCEL_ON_BEHALF_DUE_TO_OPERATIONAL_ERROR_EFFECTIVE (NOT VALID FOR ORDER MASS ACTION REQUEST)"
  end
  if value == 0 then
    return "Exec restatement reason: NULL"
  end

  return "Exec Restatement Reason: UNKNOWN("..value..")"
end

-- Dissect: Mass Cancel Restatement Reason
b3_entrypoint_sbe_dissect.mass_cancel_restatement_reason = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.mass_cancel_restatement_reason
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.mass_cancel_restatement_reason(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.mass_cancel_restatement_reason, range, value, display)

  return offset + length, value
end

-- Size: Mass Action Reject Reason
b3_entrypoint_sbe_size_of.mass_action_reject_reason = 1

-- Display: Mass Action Reject Reason
b3_entrypoint_sbe_display.mass_action_reject_reason = function(value)
  if value == 0 then
    return "Reject reason: MASS_ACTION_NOT_SUPPORTED"
  end
  if value == 8 then
    return "Reject reason: INVALID_OR_UNKNOWN_MARKET_SEGMENT"
  end
  if value == 99 then
    return "Reject reason: OTHER"
  end
  if value == 255 then
    return "Reject reason: NULL"
  end

  return "Reject reason: UNKNOWN("..value..")"
end

-- Dissect: Mass Action Reject Reason
b3_entrypoint_sbe_dissect.mass_action_reject_reason = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.mass_action_reject_reason
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.mass_action_reject_reason(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.mass_action_reject_reason, range, value, display)

  return offset + length, value
end

-- Size: Mass Action Response
b3_entrypoint_sbe_size_of.mass_action_response = 1

-- Display: Mass Action Response
b3_entrypoint_sbe_display.mass_action_response = function(value)
  if value == "0" then
    return "Mass action response: REJECTED"
  end
  if value == "1" then
    return "Mass action response: ACCEPTED"
  end

  return "Mass action response: UNKNOWN("..value..")"
end

-- Dissect: Mass Action Response
b3_entrypoint_sbe_dissect.mass_action_response = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.mass_action_response
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()

  -- check if value is non zero
  if value == 0 then
    value = ''
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.mass_action_response(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.mass_action_response, range, value, display)

  return offset + length, value
end

-- Size: Transact Time
b3_entrypoint_sbe_size_of.transact_time = 8

-- Display: Transact Time
b3_entrypoint_sbe_display.transact_time = function(value)
  return "Transact time: "..value
end

-- Dissect: Transact Time
b3_entrypoint_sbe_dissect.transact_time = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.transact_time
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.transact_time(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.transact_time, range, value, display)

  return offset + length, value
end

-- Size: Mass Action Report ID
b3_entrypoint_sbe_size_of.mass_action_report_id = 8

-- Display: Mass Action Report ID
b3_entrypoint_sbe_display.mass_action_report_id = function(value)
  return "Mass action report ID: "..value
end

-- Dissect: Mass Action Report ID
b3_entrypoint_sbe_dissect.mass_action_report_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.mass_action_report_id
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.mass_action_report_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.mass_action_report_id, range, value, display)

  return offset + length, value
end

-- Size: ClOrdId
b3_entrypoint_sbe_size_of.clordid = 8

-- Display: ClOrdId
b3_entrypoint_sbe_display.clordid = function(value)
  return "Client order ID: "..value
end

-- Dissect: ClOrdId
b3_entrypoint_sbe_dissect.clordid = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.clordid
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.clordid(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.clordid, range, value, display)

  return offset + length, value
end

-- Size: Mass Action Scope
b3_entrypoint_sbe_size_of.mass_action_scope = 1

-- Display: Mass Action Scope
b3_entrypoint_sbe_display.mass_action_scope = function(value)
  if value == 6 then
    return "Mass action scope: ALL_ORDERS_FOR_A_TRADING_SESSION"
  end
  if value == 0 then
    return "Mass action scope: NULL"
  end

  return "Mass action scope: UNKNOWN("..value..")"
end

-- Dissect: Mass Action Scope
b3_entrypoint_sbe_dissect.mass_action_scope = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.mass_action_scope
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.mass_action_scope(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.mass_action_scope, range, value, display)

  return offset + length, value
end

-- Size: Mass Action Type
b3_entrypoint_sbe_size_of.mass_action_type = 1

-- Display: Mass Action Type
b3_entrypoint_sbe_display.mass_action_type = function(value)
  if value == 2 then
    return "Mass action type: RELEASE_ORDERS_FROM_SUSPENSION"
  end
  if value == 3 then
    return "Mass action type: CANCEL_ORDERS"
  end
  if value == 4 then
    return "Mass action type: CANCEL_AND_SUSPEND_ORDERS"
  end

  return "Mass Action Type: UNKNOWN("..value..")"
end

-- Dissect: Mass Action Type
b3_entrypoint_sbe_dissect.mass_action_type = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.mass_action_type
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.mass_action_type(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.mass_action_type, range, value, display)

  return offset + length, value
end

-- Size: Outbound Business Header
b3_entrypoint_sbe_size_of.outbound_business_header = 18

-- Display: Inbound Business Header
b3_entrypoint_sbe_display.outbound_business_header = function(buffer, packet, parent)
  return ""
end

-- Dissect Fields: Simple Open Framing Header
b3_entrypoint_sbe_dissect.outbound_business_header_fields = function(buffer, offset, packet, parent)
  local index = offset

  index, session_id = b3_entrypoint_sbe_dissect.session_id(buffer, index, packet, parent)

  index, msg_seq_num = b3_entrypoint_sbe_dissect.msg_seq_num(buffer, index, packet, parent)

  index, sending_time = b3_entrypoint_sbe_dissect.sending_time(buffer, index, packet, parent)

  index, poss_resend = b3_entrypoint_sbe_dissect.poss_resend(buffer, index, packet, parent)

  return index
end

-- Dissect: Simple Open Framing Header
b3_entrypoint_sbe_dissect.outbound_business_header = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.inbound_business_header then
    local length = b3_entrypoint_sbe_size_of.outbound_business_header(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.outbound_business_header(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.outbound_business_header, range, display)
  end

  return b3_entrypoint_sbe_dissect.outbound_business_header_fields(buffer, offset, packet, parent)
end

-- Calculate size of: Order Mass Action Report Message
b3_entrypoint_sbe_size_of.order_mass_action_report_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.outbound_business_header

  index = index + b3_entrypoint_sbe_size_of.mass_action_type

  index = index + b3_entrypoint_sbe_size_of.mass_action_scope

  index = index + b3_entrypoint_sbe_size_of.clordid

  index = index + b3_entrypoint_sbe_size_of.mass_action_report_id

  index = index + b3_entrypoint_sbe_size_of.transact_time

  index = index + b3_entrypoint_sbe_size_of.mass_action_response

  index = index + b3_entrypoint_sbe_size_of.mass_action_reject_reason

  index = index + b3_entrypoint_sbe_size_of.mass_cancel_restatement_reason

  index = index + b3_entrypoint_sbe_size_of.ord_tag_id

  index = index + b3_entrypoint_sbe_size_of.side

  -- Padding 1 Byte
  index = index + 1

  index = index + b3_entrypoint_sbe_size_of.asset

  index = index + b3_entrypoint_sbe_size_of.security_id_optional

  index = index + b3_entrypoint_sbe_size_of.investor_id

  index = index + b3_entrypoint_sbe_size_of.text(buffer, offset + index)

  return index
end

-- Display: Order Mass Action Report Message
b3_entrypoint_sbe_display.order_mass_action_report_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Order Mass Action Report Message
b3_entrypoint_sbe_dissect.order_mass_action_report_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Outbound Business Header: 1 Byte Ascii String
  index, outbound_business_header = b3_entrypoint_sbe_dissect.outbound_business_header(buffer, index, packet, parent)

  -- Mass Action Type: 1 Byte Unsigned Fixed Width Integer Enum with 3 values
  index, mass_action_type = b3_entrypoint_sbe_dissect.mass_action_type(buffer, index, packet, parent)

  -- Mass Action Scope: 1 Byte Unsigned Fixed Width Integer Enum with 2 values
  index, mass_action_scope = b3_entrypoint_sbe_dissect.mass_action_scope(buffer, index, packet, parent)

  -- ClOrdId: 8 Byte Unsigned Fixed Width Integer
  index, clordid = b3_entrypoint_sbe_dissect.clordid(buffer, index, packet, parent)

  -- Mass Action Report ID: 8 Byte Unsigned Fixed Width Integer
  index, mass_action_report_id = b3_entrypoint_sbe_dissect.mass_action_report_id(buffer, index, packet, parent)

  -- Transact Time: 8 Byte Unsigned Fixed Width Integer
  index, transact_time = b3_entrypoint_sbe_dissect.transact_time(buffer, index, packet, parent)

  -- Mass Action Response: 1 Byte Ascii String Enum with 2 values
  index, mass_action_response = b3_entrypoint_sbe_dissect.mass_action_response(buffer, index, packet, parent)

  -- Mass Action Reject Reason: 1 Byte Unsigned Fixed Width Integer Enum with 4 values
  index, mass_action_reject_reason = b3_entrypoint_sbe_dissect.mass_action_reject_reason(buffer, index, packet, parent)

  -- Mass Cancel Restatement Reason: 1 Byte Unsigned Fixed Width Integer Enum with 3 values
  index, mass_cancel_restatement_reason = b3_entrypoint_sbe_dissect.mass_cancel_restatement_reason(buffer, index, packet, parent)

  -- Ord Tag ID: 1 Byte Unsigned Fixed Width Integer
  index, ord_tag_id = b3_entrypoint_sbe_dissect.ord_tag_id(buffer, index, packet, parent)

  -- Side Optional: 1 Byte Ascii String Enum with 3 values
  index, side = b3_entrypoint_sbe_dissect.side_optional(buffer, index, packet, parent)

  -- Padding 1 Byte
  index = index + 1

  -- Asset: 6 Byte Ascii String
  index, asset = b3_entrypoint_sbe_dissect.asset(buffer, index, packet, parent)

  -- Security ID Optional: 8 Byte Unsigned Fixed Width Integer
  index, security_id_optional = b3_entrypoint_sbe_dissect.security_id_optional(buffer, index, packet, parent)

  -- Investor ID: 2 Byte (Prefix) + 2 (Padding) + 6 Byte (Document)
  index, investor_id = b3_entrypoint_sbe_dissect.investor_id(buffer, index, packet, parent)

  -- Text: 1 Byte (Length) + N Bytes
  index, text = b3_entrypoint_sbe_dissect.text(buffer, index, packet, parent)

  return index
end

-- Dissect: Order Mass Action Report Message
b3_entrypoint_sbe_dissect.order_mass_action_report_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.order_mass_action_report_message then
    local length = b3_entrypoint_sbe_size_of.order_mass_action_report_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.order_mass_action_report_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.order_mass_action_report_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.order_mass_action_report_message_fields(buffer, offset, packet, parent)
end

b3_entrypoint_sbe_size_of.inbound_business_header = 18

-- Display: Inbound Business Header
b3_entrypoint_sbe_display.inbound_business_header = function(buffer, packet, parent)
  return ""
end

-- Dissect Fields: Simple Open Framing Header
b3_entrypoint_sbe_dissect.inbound_business_header_fields = function(buffer, offset, packet, parent)
  local index = offset

  index, session_id = b3_entrypoint_sbe_dissect.session_id(buffer, index, packet, parent)

  index, msg_seq_num = b3_entrypoint_sbe_dissect.msg_seq_num(buffer, index, packet, parent)

  index, sending_time = b3_entrypoint_sbe_dissect.sending_time(buffer, index, packet, parent)

  index, market_segment_id = b3_entrypoint_sbe_dissect.market_segment_id(buffer, index, packet, parent)

  return index + 1
end

-- Dissect: Simple Open Framing Header
b3_entrypoint_sbe_dissect.inbound_business_header = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.inbound_business_header then
    local length = b3_entrypoint_sbe_size_of.inbound_business_header(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.inbound_business_header(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.inbound_business_header, range, display)
  end

  return b3_entrypoint_sbe_dissect.inbound_business_header_fields(buffer, offset, packet, parent)
end

-- Calculate size of: Order Mass Action Request Message
b3_entrypoint_sbe_size_of.order_mass_action_request_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.inbound_business_header

  index = index + b3_entrypoint_sbe_size_of.mass_action_type

  index = index + b3_entrypoint_sbe_size_of.mass_action_scope

  index = index + b3_entrypoint_sbe_size_of.clordid

  index = index + b3_entrypoint_sbe_size_of.mass_cancel_restatement_reason

  index = index + b3_entrypoint_sbe_size_of.ord_tag_id

  index = index + b3_entrypoint_sbe_size_of.side

  index = index + b3_entrypoint_sbe_size_of.asset

  index = index + 1

  index = index + b3_entrypoint_sbe_size_of.security_id_optional

  index = index + b3_entrypoint_sbe_size_of.investor_id

  return index
end

-- Display: Order Mass Action Request Message
b3_entrypoint_sbe_display.order_mass_action_request_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Order Mass Action Request Message
b3_entrypoint_sbe_dissect.order_mass_action_request_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Inbound Business Header: 1 Byte Ascii String
  index, inbound_business_header = b3_entrypoint_sbe_dissect.inbound_business_header(buffer, index, packet, parent)

  -- Mass Action Type: 1 Byte Unsigned Fixed Width Integer Enum with 3 values
  index, mass_action_type = b3_entrypoint_sbe_dissect.mass_action_type(buffer, index, packet, parent)

  -- Mass Action Scope: 1 Byte Unsigned Fixed Width Integer Enum with 2 values
  index, mass_action_scope = b3_entrypoint_sbe_dissect.mass_action_scope(buffer, index, packet, parent)

  -- ClOrdId: 8 Byte Unsigned Fixed Width Integer
  index, clordid = b3_entrypoint_sbe_dissect.clordid(buffer, index, packet, parent)

  -- Mass Cancel Restatement Reason: 1 Byte Unsigned Fixed Width Integer Enum with 3 values
  index, mass_cancel_restatement_reason = b3_entrypoint_sbe_dissect.mass_cancel_restatement_reason(buffer, index, packet, parent)

  -- Ord Tag ID: 1 Byte Unsigned Fixed Width Integer
  index, ord_tag_id = b3_entrypoint_sbe_dissect.ord_tag_id(buffer, index, packet, parent)

  -- Side Optional: 1 Byte Ascii String Enum with 3 values
  index, side = b3_entrypoint_sbe_dissect.side_optional(buffer, index, packet, parent)

  index = index + 1

  -- Asset: 6 Byte Ascii String
  index, asset = b3_entrypoint_sbe_dissect.asset(buffer, index, packet, parent)

  -- Security ID Optional: 8 Byte Unsigned Fixed Width Integer
  index, security_id_optional = b3_entrypoint_sbe_dissect.security_id_optional(buffer, index, packet, parent)

  -- Investor ID: 2 Byte (Prefix) + 2 (Padding) + 6 Byte (Document)
  index, investor_id = b3_entrypoint_sbe_dissect.investor_id(buffer, index, packet, parent)

  return index
end

-- Dissect: Order Mass Action Request Message
b3_entrypoint_sbe_dissect.order_mass_action_request_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.order_mass_action_request_message then
    local length = b3_entrypoint_sbe_size_of.order_mass_action_request_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.order_mass_action_request_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.order_mass_action_request_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.order_mass_action_request_message_fields(buffer, offset, packet, parent)
end

-- Size: Entering Trader
b3_entrypoint_sbe_size_of.entering_trader = 5

-- Display: Entering Trader
b3_entrypoint_sbe_display.entering_trader = function(value)
  -- Check if field has value
  if value == nil or value == '' then
    return "Entering trader: NULL"
  end

  return "Entering trader: "..value
end

-- Dissect: Entering Trader
b3_entrypoint_sbe_dissect.entering_trader = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.entering_trader
  local range = buffer(offset, length)

  -- parse last octet
  local last = buffer(offset + length - 1, 1):uint()

  -- read full string or up to first zero
  local value = ''
  if last == 0 then
    value = range:stringz()
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.entering_trader(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.entering_trader, range, value, display)

  return offset + length, value
end

-- Size: Sender Location
b3_entrypoint_sbe_size_of.sender_location = 10

-- Display: Sender Location
b3_entrypoint_sbe_display.sender_location = function(value)
  -- Check if field has value
  if value == nil or value == '' then
    return "Sender location: NULL"
  end

  return "Sender location: "..value
end

-- Dissect: Sender Location
b3_entrypoint_sbe_dissect.sender_location = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.sender_location
  local range = buffer(offset, length)

  -- parse last octet
  local last = buffer(offset + length - 1, 1):uint()

  -- read full string or up to first zero
  local value = ''
  if last == 0 then
    value = range:stringz()
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.sender_location(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.sender_location, range, value, display)

  return offset + length, value
end

-- Size: Side
b3_entrypoint_sbe_size_of.side = 1

-- Display: Side
b3_entrypoint_sbe_display.side = function(value, optional)
  if value == 49 then
    return "Side: BUY"
  end
  if value == 50 then
    return "Side: SELL"
  end
  if value == 0 and optional then
    return "Side: NULL"
  end
  if value == 0 and not optional then
    return "Side: INVALID (NULL), only valid for optional field"
  end

  return "Side: UNKNOWN("..value..")"
end

-- Dissect: Side
b3_entrypoint_sbe_dissect.side = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.side
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()

  local display = b3_entrypoint_sbe_display.side(value, false, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.side, range, value, display)

  return offset + length, value
end

-- Size: Trade Date Optional
b3_entrypoint_sbe_size_of.trade_date_optional = 2

-- Display: Trade Date Optional
b3_entrypoint_sbe_display.trade_date_optional = function(value)
  return "Trade date: "..value
end

-- Dissect: Trade Date Optional
b3_entrypoint_sbe_dissect.trade_date_optional = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.trade_date_optional
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.trade_date_optional(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.trade_date_optional, range, value, display)

  return offset + length, value
end

-- Size: Alloc Status
b3_entrypoint_sbe_size_of.alloc_status = 1

-- Display: Alloc Status
b3_entrypoint_sbe_display.alloc_status = function(value)
  if value == "0" then
    return "Allocation status: ACCEPTED"
  end
  if value == "5" then
    return "Allocation status: REJECTED_BY_INTERMEDIARY"
  end

  return "Allocation status: UNKNOWN("..value..")"
end

-- Dissect: Alloc Status
b3_entrypoint_sbe_dissect.alloc_status = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.alloc_status
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()

  -- check if value is non zero
  if value == 0 then
    value = ''
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.alloc_status(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.alloc_status, range, value, display)

  return offset + length, value
end

-- Size: Quantity
b3_entrypoint_sbe_size_of.quantity = 8

-- Display: Quantity
b3_entrypoint_sbe_display.quantity = function(value)
  return "Quantity: "..value
end

-- Dissect: Quantity
b3_entrypoint_sbe_dissect.quantity = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.quantity
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.quantity(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.quantity, range, value, display)

  return offset + length, value
end

-- Size: Max Sweep Qty
b3_entrypoint_sbe_size_of.max_sweep_qty = 8

-- Display: Max Sweep Qty
b3_entrypoint_sbe_display.max_sweep_qty = function(value)
  return "Max Sweep Qty: "..value
end

-- Dissect: Max Sweep Qty
b3_entrypoint_sbe_dissect.max_sweep_qty = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.max_sweep_qty
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.max_sweep_qty(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.max_sweep_qty, range, value, display)

  return offset + length, value
end

-- Size: Alloc Rej Code
b3_entrypoint_sbe_size_of.alloc_rej_code = 4

-- Display: Alloc Rej Code
b3_entrypoint_sbe_display.alloc_rej_code = function(value)
  return "Allocation reject code: "..value
end

-- Dissect: Alloc Rej Code
b3_entrypoint_sbe_dissect.alloc_rej_code = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.alloc_rej_code
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.alloc_rej_code(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.alloc_rej_code, range, value, display)

  return offset + length, value
end

-- Size: Alloc No Orders Type
b3_entrypoint_sbe_size_of.alloc_no_orders_type = 1

-- Display: Alloc No Orders Type
b3_entrypoint_sbe_display.alloc_no_orders_type = function(value)
  if value == "0" then
    return "Allocation no orders type: NOT_SPECIFIED"
  end

  return "Allocation no orders type: UNKNOWN("..value..")"
end

-- Dissect: Alloc No Orders Type
b3_entrypoint_sbe_dissect.alloc_no_orders_type = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.alloc_no_orders_type
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()

  -- check if value is non zero
  if value == 0 then
    value = ''
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.alloc_no_orders_type(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.alloc_no_orders_type, range, value, display)

  return offset + length, value
end

-- Size: Alloc Report Type
b3_entrypoint_sbe_size_of.alloc_report_type = 1

-- Display: Alloc Report Type
b3_entrypoint_sbe_display.alloc_report_type = function(value)
  if value == "8" then
    return "Allocation report type: REQUEST_TO_INTERMEDIARY"
  end

  return "Allocation report type: UNKNOWN("..value..")"
end

-- Dissect: Alloc Report Type
b3_entrypoint_sbe_dissect.alloc_report_type = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.alloc_report_type
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()

  -- check if value is non zero
  if value == 0 then
    value = ''
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.alloc_report_type(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.alloc_report_type, range, value, display)

  return offset + length, value
end

-- Size: Alloc Trans Type
b3_entrypoint_sbe_size_of.alloc_trans_type = 1

-- Display: Alloc Trans Type
b3_entrypoint_sbe_display.alloc_trans_type = function(value)
  if value == "0" then
    return "Allocation transaction type: NEW"
  end
  if value == "2" then
    return "Allocation transaction type: CANCEL"
  end

  return "Allocation transaction Type: UNKNOWN("..value..")"
end

-- Dissect: Alloc Trans Type
b3_entrypoint_sbe_dissect.alloc_trans_type = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.alloc_trans_type
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()

  -- check if value is non zero
  if value == 0 then
    value = ''
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.alloc_trans_type(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.alloc_trans_type, range, value, display)

  return offset + length, value
end

-- Size: Alloc Report ID
b3_entrypoint_sbe_size_of.alloc_report_id = 8

-- Display: Alloc Report ID
b3_entrypoint_sbe_display.alloc_report_id = function(value)
  return "Allocation report ID: "..value
end

-- Dissect: Alloc Report ID
b3_entrypoint_sbe_dissect.alloc_report_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.alloc_report_id
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.alloc_report_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.alloc_report_id, range, value, display)

  return offset + length, value
end

-- Size: Security ID
b3_entrypoint_sbe_size_of.security_id = 8

-- Display: Security ID
b3_entrypoint_sbe_display.security_id = function(value)
  return "Security ID: "..value
end

-- Dissect: Security ID
b3_entrypoint_sbe_dissect.security_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.security_id
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.security_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.security_id, range, value, display)

  return offset + length, value
end

-- Size: Alloc ID
b3_entrypoint_sbe_size_of.alloc_id = 8

-- Display: Alloc ID
b3_entrypoint_sbe_display.alloc_id = function(value)
  return "Allocation ID: "..value
end

-- Dissect: Alloc ID
b3_entrypoint_sbe_dissect.alloc_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.alloc_id
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.alloc_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.alloc_id, range, value, display)

  return offset + length, value
end

-- Calculate size of: Allocation Report Message
b3_entrypoint_sbe_size_of.allocation_report_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.outbound_business_header

  index = index + b3_entrypoint_sbe_size_of.alloc_id

  index = index + b3_entrypoint_sbe_size_of.security_id

  index = index + b3_entrypoint_sbe_size_of.security_exchange

  index = index + b3_entrypoint_sbe_size_of.alloc_report_id

  index = index + b3_entrypoint_sbe_size_of.alloc_trans_type

  index = index + b3_entrypoint_sbe_size_of.alloc_report_type

  index = index + b3_entrypoint_sbe_size_of.alloc_no_orders_type

  index = index + b3_entrypoint_sbe_size_of.alloc_rej_code

  index = index + b3_entrypoint_sbe_size_of.quantity

  index = index + b3_entrypoint_sbe_size_of.alloc_status

  index = index + b3_entrypoint_sbe_size_of.trade_date_optional

  index = index + b3_entrypoint_sbe_size_of.transact_time

  index = index + b3_entrypoint_sbe_size_of.side

  index = index + b3_entrypoint_sbe_size_of.sender_location

  index = index + b3_entrypoint_sbe_size_of.entering_trader

  return index
end

-- Display: Allocation Report Message
b3_entrypoint_sbe_display.allocation_report_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Allocation Report Message
b3_entrypoint_sbe_dissect.allocation_report_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Outbound Business Header: 1 Byte Ascii String
  index, outbound_business_header = b3_entrypoint_sbe_dissect.outbound_business_header(buffer, index, packet, parent)

  -- Alloc ID: 8 Byte Unsigned Fixed Width Integer
  index, alloc_id = b3_entrypoint_sbe_dissect.alloc_id(buffer, index, packet, parent)

  -- Security ID: 8 Byte Unsigned Fixed Width Integer
  index, security_id = b3_entrypoint_sbe_dissect.security_id(buffer, index, packet, parent)

  -- Alloc Report ID: 8 Byte Unsigned Fixed Width Integer
  index, alloc_report_id = b3_entrypoint_sbe_dissect.alloc_report_id(buffer, index, packet, parent)

  -- Alloc Trans Type: 1 Byte Ascii String Enum with 2 values
  index, alloc_trans_type = b3_entrypoint_sbe_dissect.alloc_trans_type(buffer, index, packet, parent)

  -- Alloc Report Type: 1 Byte Ascii String Enum with 1 values
  index, alloc_report_type = b3_entrypoint_sbe_dissect.alloc_report_type(buffer, index, packet, parent)

  -- Alloc No Orders Type: 1 Byte Ascii String Enum with 1 values
  index, alloc_no_orders_type = b3_entrypoint_sbe_dissect.alloc_no_orders_type(buffer, index, packet, parent)

  -- Alloc Rej Code: 4 Byte Unsigned Fixed Width Integer
  index, alloc_rej_code = b3_entrypoint_sbe_dissect.alloc_rej_code(buffer, index, packet, parent)

  -- Quantity: 8 Byte Unsigned Fixed Width Integer
  index, quantity = b3_entrypoint_sbe_dissect.quantity(buffer, index, packet, parent)

  -- Alloc Status: 1 Byte Ascii String Enum with 2 values
  index, alloc_status = b3_entrypoint_sbe_dissect.alloc_status(buffer, index, packet, parent)

  -- Trade Date Optional: 2 Byte Unsigned Fixed Width Integer
  index, trade_date_optional = b3_entrypoint_sbe_dissect.trade_date_optional(buffer, index, packet, parent)

  -- Transact Time: 8 Byte Unsigned Fixed Width Integer
  index, transact_time = b3_entrypoint_sbe_dissect.transact_time(buffer, index, packet, parent)

  -- Side: 1 Byte Ascii String Enum with 2 values
  index, side = b3_entrypoint_sbe_dissect.side(buffer, index, packet, parent)

  -- Sender Location: 10 Byte Ascii String
  index, sender_location = b3_entrypoint_sbe_dissect.sender_location(buffer, index, packet, parent)

  -- Entering Trader: 5 Byte Ascii String
  index, entering_trader = b3_entrypoint_sbe_dissect.entering_trader(buffer, index, packet, parent)

  return index
end

-- Dissect: Allocation Report Message
b3_entrypoint_sbe_dissect.allocation_report_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.allocation_report_message then
    local length = b3_entrypoint_sbe_size_of.allocation_report_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.allocation_report_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.allocation_report_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.allocation_report_message_fields(buffer, offset, packet, parent)
end

b3_entrypoint_sbe_dissect.asset = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.asset
  local range = buffer(offset, length)

  -- parse last octet
  local last = buffer(offset + length - 1, 1):uint()

  -- read full string or up to first zero
  local value = ''
  if last == 0 then
    value = range:stringz()
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.asset(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.asset, range, value, display)

  return offset + length, value
end

-- Size: Alloc Qty
b3_entrypoint_sbe_size_of.alloc_qty = 8

-- Display: Alloc Qty
b3_entrypoint_sbe_display.alloc_qty = function(value)
  return "Quantity: "..value
end

-- Dissect: Alloc Qty
b3_entrypoint_sbe_dissect.alloc_qty = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.alloc_qty
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.alloc_qty(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.alloc_qty, range, value, display)

  return offset + length, value
end

-- Size: Alloc Account
b3_entrypoint_sbe_size_of.alloc_account = 4

-- Display: Alloc Account
b3_entrypoint_sbe_display.alloc_account = function(value)
  return "Allocation account: "..value
end

-- Dissect: Alloc Account
b3_entrypoint_sbe_dissect.alloc_account = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.alloc_account
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.alloc_account(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.alloc_account, range, value, display)

  return offset + length, value
end

-- Size: Individual Alloc ID
b3_entrypoint_sbe_size_of.individual_alloc_id = 8

-- Display: Individual Alloc ID
b3_entrypoint_sbe_display.individual_alloc_id = function(value)
  return "Individual allocation ID: "..value
end

-- Dissect: Individual Alloc ID
b3_entrypoint_sbe_dissect.individual_alloc_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.individual_alloc_id
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.individual_alloc_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.individual_alloc_id, range, value, display)

  return offset + length, value
end

-- Size: Trade ID
b3_entrypoint_sbe_size_of.trade_id = 4

-- Display: Trade ID
b3_entrypoint_sbe_display.trade_id = function(value)
  return "Trade ID: "..value
end

-- Dissect: Trade ID
b3_entrypoint_sbe_dissect.trade_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.trade_id
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.trade_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.trade_id, range, value, display)

  return offset + length, value
end

b3_entrypoint_sbe_size_of.event_id = 4
b3_entrypoint_sbe_display.event_id = function(value)
  return "Event ID: "..value
end

b3_entrypoint_sbe_dissect.event_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.event_id
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.event_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.event_id, range, value, display)

  return offset + length, value
end

b3_entrypoint_sbe_size_of.no_related_trades = 2

b3_entrypoint_sbe_display.no_related_trades = function(value)
  return "Related trades: "..value
end

b3_entrypoint_sbe_dissect.no_related_trades = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.no_related_trades
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.no_related_trades(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.no_related_trades, range, value, display)

  return offset + length, value
end

-- Size: Alloc Type
b3_entrypoint_sbe_size_of.alloc_type = 1

-- Display: Alloc Type
b3_entrypoint_sbe_display.alloc_type = function(value)
  if value == "8" then
    return "Allocation Type: REQUEST_TO_INTERMEDIARY"
  end

  return "Allocation Type: UNKNOWN("..value..")"
end

-- Dissect: Alloc Type
b3_entrypoint_sbe_dissect.alloc_type = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.alloc_type
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()

  -- check if value is non zero
  if value == 0 then
    value = ''
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.alloc_type(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.alloc_type, range, value, display)

  return offset + length, value
end

-- Calculate size of: Allocation Instruction Message
b3_entrypoint_sbe_size_of.allocation_instruction_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.inbound_business_header

  index = index + b3_entrypoint_sbe_size_of.alloc_id

  index = index + b3_entrypoint_sbe_size_of.security_id

  index = index + b3_entrypoint_sbe_size_of.alloc_trans_type

  index = index + b3_entrypoint_sbe_size_of.alloc_type

  index = index + b3_entrypoint_sbe_size_of.alloc_no_orders_type

  index = index + b3_entrypoint_sbe_size_of.quantity

  index = index + b3_entrypoint_sbe_size_of.sender_location

  index = index + b3_entrypoint_sbe_size_of.entering_trader

  index = index + b3_entrypoint_sbe_size_of.trade_id

  index = index + b3_entrypoint_sbe_size_of.trade_date_optional

  index = index + b3_entrypoint_sbe_size_of.individual_alloc_id

  index = index + b3_entrypoint_sbe_size_of.alloc_account

  index = index + b3_entrypoint_sbe_size_of.alloc_qty

  return index
end

-- Display: Allocation Instruction Message
b3_entrypoint_sbe_display.allocation_instruction_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Allocation Instruction Message
b3_entrypoint_sbe_dissect.allocation_instruction_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Inbound Business Header: 1 Byte Ascii String
  index, inbound_business_header = b3_entrypoint_sbe_dissect.inbound_business_header(buffer, index, packet, parent)

  -- Alloc ID: 8 Byte Unsigned Fixed Width Integer
  index, alloc_id = b3_entrypoint_sbe_dissect.alloc_id(buffer, index, packet, parent)

  -- Security ID: 8 Byte Unsigned Fixed Width Integer
  index, security_id = b3_entrypoint_sbe_dissect.security_id(buffer, index, packet, parent)

  -- Alloc Trans Type: 1 Byte Ascii String Enum with 2 values
  index, alloc_trans_type = b3_entrypoint_sbe_dissect.alloc_trans_type(buffer, index, packet, parent)

  -- Alloc Type: 1 Byte Ascii String Enum with 1 values
  index, alloc_type = b3_entrypoint_sbe_dissect.alloc_type(buffer, index, packet, parent)

  -- Alloc No Orders Type: 1 Byte Ascii String Enum with 1 values
  index, alloc_no_orders_type = b3_entrypoint_sbe_dissect.alloc_no_orders_type(buffer, index, packet, parent)

  -- Quantity: 8 Byte Unsigned Fixed Width Integer
  index, quantity = b3_entrypoint_sbe_dissect.quantity(buffer, index, packet, parent)

  -- Sender Location: 10 Byte Ascii String
  index, sender_location = b3_entrypoint_sbe_dissect.sender_location(buffer, index, packet, parent)

  -- Entering Trader: 5 Byte Ascii String
  index, entering_trader = b3_entrypoint_sbe_dissect.entering_trader(buffer, index, packet, parent)

  -- Trade ID: 4 Byte Unsigned Fixed Width Integer
  index, trade_id = b3_entrypoint_sbe_dissect.trade_id(buffer, index, packet, parent)

  -- Trade Date Optional: 2 Byte Unsigned Fixed Width Integer
  index, trade_date_optional = b3_entrypoint_sbe_dissect.trade_date_optional(buffer, index, packet, parent)

  -- Individual Alloc ID: 8 Byte Unsigned Fixed Width Integer
  index, individual_alloc_id = b3_entrypoint_sbe_dissect.individual_alloc_id(buffer, index, packet, parent)

  -- Alloc Account: 4 Byte Unsigned Fixed Width Integer
  index, alloc_account = b3_entrypoint_sbe_dissect.alloc_account(buffer, index, packet, parent)

  -- Alloc Qty: 8 Byte Unsigned Fixed Width Integer
  index, alloc_qty = b3_entrypoint_sbe_dissect.alloc_qty(buffer, index, packet, parent)

  return index
end

-- Dissect: Allocation Instruction Message
b3_entrypoint_sbe_dissect.allocation_instruction_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.allocation_instruction_message then
    local length = b3_entrypoint_sbe_size_of.allocation_instruction_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.allocation_instruction_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.allocation_instruction_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.allocation_instruction_message_fields(buffer, offset, packet, parent)
end

-- Size: Short Qty
b3_entrypoint_sbe_size_of.short_qty = 8

-- Display: Short Qty
b3_entrypoint_sbe_display.short_qty = function(value)
  return "Quantity: "..value
end

-- Dissect: Short Qty
b3_entrypoint_sbe_dissect.short_qty = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.short_qty
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.short_qty(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.short_qty, range, value, display)

  return offset + length, value
end

-- Size: Long Qty Optional
b3_entrypoint_sbe_size_of.long_qty_optional = 8

-- Display: Long Qty Optional
b3_entrypoint_sbe_display.long_qty_optional = function(value)
  return "Quantity: "..value
end

-- Dissect: Long Qty Optional
b3_entrypoint_sbe_dissect.long_qty_optional = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.long_qty_optional
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.long_qty_optional(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.long_qty_optional, range, value, display)

  return offset + length, value
end

-- Size: Pos Type
b3_entrypoint_sbe_size_of.pos_type = 1

-- Display: Pos Type
b3_entrypoint_sbe_display.pos_type = function(value)
  if value == "T" then
    return "Quantity type: TRANSACTION_QUANTITY"
  end
  if value == "S" then
    return "Quantity type: START_OF_DAY_QTY"
  end
  if value == "E" then
    return "Quantity type: OPTION_EXERCISE_QTY"
  end
  if value == "B" then
    return "Quantity type: BLOCKED_QTY"
  end
  if value == "U" then
    return "Quantity type: UNCOVERED_QTY"
  end
  if value == "C" then
    return "Quantity type: COVERED_QTY"
  end

  return "Quantity type: UNKNOWN("..value..")"
end

-- Dissect: Pos Type
b3_entrypoint_sbe_dissect.pos_type = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.pos_type
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()

  -- check if value is non zero
  if value == 0 then
    value = ''
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.pos_type(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.pos_type, range, value, display)

  return offset + length, value
end

-- Calculate size of: No Positions Group
b3_entrypoint_sbe_size_of.no_positions_group = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.pos_type

  index = index + b3_entrypoint_sbe_size_of.long_qty_optional

  index = index + b3_entrypoint_sbe_size_of.short_qty

  return index
end

-- Display: No Positions Group
b3_entrypoint_sbe_display.no_positions_group = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: No Positions Group
b3_entrypoint_sbe_dissect.no_positions_group_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Pos Type: 1 Byte Ascii String Enum with 6 values
  index, pos_type = b3_entrypoint_sbe_dissect.pos_type(buffer, index, packet, parent)

  -- Long Qty Optional: 8 Byte Unsigned Fixed Width Integer
  index, long_qty_optional = b3_entrypoint_sbe_dissect.long_qty_optional(buffer, index, packet, parent)

  -- Short Qty: 8 Byte Unsigned Fixed Width Integer
  index, short_qty = b3_entrypoint_sbe_dissect.short_qty(buffer, index, packet, parent)

  return index
end

-- Dissect: No Positions Group
b3_entrypoint_sbe_dissect.no_positions_group = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.no_positions_group then
    local length = b3_entrypoint_sbe_size_of.no_positions_group(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.no_positions_group(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.no_positions_group, range, display)
  end

  return b3_entrypoint_sbe_dissect.no_positions_group_fields(buffer, offset, packet, parent)
end

-- Size: Num In Group
b3_entrypoint_sbe_size_of.num_in_group = 1

-- Display: Num In Group
b3_entrypoint_sbe_display.num_in_group = function(value)
  return "Num in group: "..value
end

-- Dissect: Num In Group
b3_entrypoint_sbe_dissect.num_in_group = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.num_in_group
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.num_in_group(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.num_in_group, range, value, display)

  return offset + length, value
end

-- Size: Block Length
b3_entrypoint_sbe_size_of.block_length = 2

-- Display: Block Length
b3_entrypoint_sbe_display.block_length = function(value)
  return "Block length: "..value
end

-- Dissect: Block Length
b3_entrypoint_sbe_dissect.block_length = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.block_length
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.block_length(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.block_length, range, value, display)

  return offset + length, value
end

-- Calculate size of: Group Size Encoding
b3_entrypoint_sbe_size_of.group_size_encoding = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.block_length

  index = index + b3_entrypoint_sbe_size_of.num_in_group

  return index
end

-- Display: Group Size Encoding
b3_entrypoint_sbe_display.group_size_encoding = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Group Size Encoding
b3_entrypoint_sbe_dissect.group_size_encoding_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Block Length: 2 Byte Unsigned Fixed Width Integer
  index, block_length = b3_entrypoint_sbe_dissect.block_length(buffer, index, packet, parent)

  -- Num In Group: 1 Byte Unsigned Fixed Width Integer
  index, num_in_group = b3_entrypoint_sbe_dissect.num_in_group(buffer, index, packet, parent)

  return index
end

-- Dissect: Group Size Encoding
b3_entrypoint_sbe_dissect.group_size_encoding = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.group_size_encoding then
    local length = b3_entrypoint_sbe_size_of.group_size_encoding(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.group_size_encoding(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.group_size_encoding, range, display)
  end

  return b3_entrypoint_sbe_dissect.group_size_encoding_fields(buffer, offset, packet, parent)
end

-- Calculate size of: No Positions Groups
b3_entrypoint_sbe_size_of.no_positions_groups = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.group_size_encoding(buffer, offset + index)

  -- Calculate field size from count
  local no_positions_group_count = buffer(offset + index - 1, 1):le_uint()
  index = index + no_positions_group_count * 17

  return index
end

-- Display: No Positions Groups
b3_entrypoint_sbe_display.no_positions_groups = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: No Positions Groups
b3_entrypoint_sbe_dissect.no_positions_groups_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Group Size Encoding: Struct of 2 fields
  index, group_size_encoding = b3_entrypoint_sbe_dissect.group_size_encoding(buffer, index, packet, parent)

  -- Dependency element: Num In Group
  local num_in_group = buffer(index - 1, 1):le_uint()

  -- No Positions Group: Struct of 3 fields
  for i = 1, num_in_group do
    index = b3_entrypoint_sbe_dissect.no_positions_group(buffer, index, packet, parent)
  end

  return index
end

-- Dissect: No Positions Groups
b3_entrypoint_sbe_dissect.no_positions_groups = function(buffer, offset, packet, parent)
  -- Optionally add dynamic struct element to protocol tree
  if show.no_positions_groups then
    local length = b3_entrypoint_sbe_size_of.no_positions_groups(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.no_positions_groups(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.no_positions_groups, range, display)
  end

  return b3_entrypoint_sbe_dissect.no_positions_groups_fields(buffer, offset, packet, parent)
end

-- Size: Contrary Instruction Indicator
b3_entrypoint_sbe_size_of.contrary_instruction_indicator = 1

-- Display: Contrary Instruction Indicator
b3_entrypoint_sbe_display.contrary_instruction_indicator = function(value)
  if value == 0 then
    return "Contrary instruction indicator: FALSE"
  end
  if value == 1 then
    return "Contrary instruction indicator: TRUE"
  end

  return "Contrary instruction indicator: UNKNOWN("..value..")"
end

-- Dissect: Contrary Instruction Indicator
b3_entrypoint_sbe_dissect.contrary_instruction_indicator = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.contrary_instruction_indicator
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.contrary_instruction_indicator(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.contrary_instruction_indicator, range, value, display)

  return offset + length, value
end

-- Size: Pos Maint Result
b3_entrypoint_sbe_size_of.pos_maint_result = 4

-- Display: Pos Maint Result
b3_entrypoint_sbe_display.pos_maint_result = function(value)
  return "Result: "..value
end

-- Dissect: Pos Maint Result
b3_entrypoint_sbe_dissect.pos_maint_result = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.pos_maint_result
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.pos_maint_result(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.pos_maint_result, range, value, display)

  return offset + length, value
end

-- Size: Account
b3_entrypoint_sbe_size_of.account = 4

-- Display: Account
b3_entrypoint_sbe_display.account = function(value)
  return "Account: "..value
end

-- Dissect: Account
b3_entrypoint_sbe_dissect.account = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.account
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.account(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.account, range, value, display)

  return offset + length, value
end

-- Size: Threshold Amount
b3_entrypoint_sbe_size_of.threshold_amount = 8

-- Display: Threshold Amount
b3_entrypoint_sbe_display.threshold_amount = function(raw, value)
  -- Check null sentinel value
  if raw == Int64(0x00000000, 0x80000000) then
    return "Threshold amount: NULL"
  end

  return "Threshold amount: "..value
end

-- Translate: Threshold Amount
translate.threshold_amount = function(raw)
  -- Check null sentinel value
  if raw == Int64(0x00000000, 0x80000000) then
    return 0/0
  end

  return raw:tonumber()/10000
end

-- Dissect: Threshold Amount
b3_entrypoint_sbe_dissect.threshold_amount = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.threshold_amount
  local range = buffer(offset, length)
  local raw = range:le_int64()
  local value = translate.threshold_amount(raw)
  local display = b3_entrypoint_sbe_display.threshold_amount(raw, value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.threshold_amount, range, value, display)

  return offset + length, value
end

-- Size: Clearing Business Date
b3_entrypoint_sbe_size_of.clearing_business_date = 2

-- Display: Clearing Business Date
b3_entrypoint_sbe_display.clearing_business_date = function(value)
  return "Clearing business date: "..value
end

-- Dissect: Clearing Business Date
b3_entrypoint_sbe_dissect.clearing_business_date = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.clearing_business_date
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.clearing_business_date(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.clearing_business_date, range, value, display)

  return offset + length, value
end

-- Size: Account Type
b3_entrypoint_sbe_size_of.account_type = 1

-- Display: Account Type
b3_entrypoint_sbe_display.account_type = function(value)
  if value == 38 then
    return "Account type: REMOVE_ACCOUNT_INFORMATION"
  end
  if value == 39 then
    return "Account type: REGULAR_ACCOUNT"
  end
  if value == 0 then
    return "Account type: NULL"
  end

  return "Account type: UNKNOWN("..value..")"
end

-- Dissect: Account Type
b3_entrypoint_sbe_dissect.account_type = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.account_type
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.account_type(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.account_type, range, value, display)

  return offset + length, value
end

-- Size: Orig Pos Req Ref ID
b3_entrypoint_sbe_size_of.orig_pos_req_ref_id = 8

-- Display: Orig Pos Req Ref ID
b3_entrypoint_sbe_display.orig_pos_req_ref_id = function(value)
  return "Original request reference ID: "..value
end

-- Dissect: Orig Pos Req Ref ID
b3_entrypoint_sbe_dissect.orig_pos_req_ref_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.orig_pos_req_ref_id
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.orig_pos_req_ref_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.orig_pos_req_ref_id, range, value, display)

  return offset + length, value
end

-- Size: Trade ID Optional
b3_entrypoint_sbe_size_of.trade_id_optional = 4

-- Display: Trade ID Optional
b3_entrypoint_sbe_display.trade_id_optional = function(value)
  return "Trade ID: "..value
end

-- Dissect: Trade ID Optional
b3_entrypoint_sbe_dissect.trade_id_optional = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.trade_id_optional
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.trade_id_optional(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.trade_id_optional, range, value, display)

  return offset + length, value
end

-- Size: Pos Maint Status
b3_entrypoint_sbe_size_of.pos_maint_status = 1

-- Display: Pos Maint Status
b3_entrypoint_sbe_display.pos_maint_status = function(value)
  if value == "0" then
    return "Status: ACCEPTED"
  end
  if value == "2" then
    return "Status: REJECTED"
  end
  if value == "3" then
    return "Status: COMPLETED"
  end
  if value == "9" then
    return "Status: NOT_EXECUTED"
  end

  return "Status: UNKNOWN("..value..")"
end

-- Dissect: Pos Maint Status
b3_entrypoint_sbe_dissect.pos_maint_status = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.pos_maint_status
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()

  -- check if value is non zero
  if value == 0 then
    value = ''
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.pos_maint_status(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.pos_maint_status, range, value, display)

  return offset + length, value
end

-- Size: Pos Maint Action
b3_entrypoint_sbe_size_of.pos_maint_action = 1

-- Display: Pos Maint Action
b3_entrypoint_sbe_display.pos_maint_action = function(value)
  if value == "1" then
    return "Action: NEW"
  end
  if value == "3" then
    return "Action: CANCEL"
  end

  return "Action: UNKNOWN("..value..")"
end

-- Dissect: Pos Maint Action
b3_entrypoint_sbe_dissect.pos_maint_action = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.pos_maint_action
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()

  -- check if value is non zero
  if value == 0 then
    value = ''
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.pos_maint_action(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.pos_maint_action, range, value, display)

  return offset + length, value
end

b3_entrypoint_sbe_size_of.cross_type = 1
b3_entrypoint_sbe_display.cross_type = function(value)
  if value == 0 then
    return "Cross type: NULL"
  end
  if value == 1 then
    return "Cross type: ALL_OR_NONE_CROSS"
  end
  if value == 4 then
    return "Cross type: CROSS_EXECUTED_AGAINST_BOOK_FROM_CLIENT"
  end

  return "Cross type: UNKNOWN("..value..")"
end

b3_entrypoint_sbe_dissect.cross_type = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.cross_type
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.cross_type(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.cross_type, range, value, display)

  return offset + length, value
end

b3_entrypoint_sbe_size_of.cross_prioritization = 1
b3_entrypoint_sbe_display.cross_prioritization = function(value)
  if value == 0 then
    return "Cross prioritization: NONE"
  end
  if value == 1 then
    return "Cross prioritization: BUY_SIDE_IS_PRIORITIZED"
  end
  if value == 2 then
    return "Cross prioritization: SELL_SIDE_IS_PRIORITIZED"
  end

  return "Cross prioritization: UNKNOWN("..value..")"
end

b3_entrypoint_sbe_dissect.cross_prioritization = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.cross_prioritization
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.cross_prioritization(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.cross_prioritization, range, value, display)

  return offset + length, value
end

-- Size: Pos Trans Type
b3_entrypoint_sbe_size_of.pos_trans_type = 1

-- Display: Pos Trans Type
b3_entrypoint_sbe_display.pos_trans_type = function(value)
  if value == 1 then
    return "Position transaction type: EXERCISE"
  end
  if value == 105 then
    return "Position transaction type: AUTOMATIC_EXERCISE"
  end
  if value == 106 then
    return "Position transaction type: EXERCISE_NOT_AUTOMATIC"
  end

  return "Position transaction type: UNKNOWN("..value..")"
end

-- Dissect: Pos Trans Type
b3_entrypoint_sbe_dissect.pos_trans_type = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.pos_trans_type
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.pos_trans_type(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.pos_trans_type, range, value, display)

  return offset + length, value
end

-- Size: Pos Maint Rpt ID
b3_entrypoint_sbe_size_of.pos_maint_rpt_id = 8

-- Display: Pos Maint Rpt ID
b3_entrypoint_sbe_display.pos_maint_rpt_id = function(value)
  return "RPT ID: "..value
end

-- Dissect: Pos Maint Rpt ID
b3_entrypoint_sbe_dissect.pos_maint_rpt_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.pos_maint_rpt_id
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.pos_maint_rpt_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.pos_maint_rpt_id, range, value, display)

  return offset + length, value
end

-- Size: Pos Req ID Optional
b3_entrypoint_sbe_size_of.pos_req_id_optional = 8

-- Display: Pos Req ID Optional
b3_entrypoint_sbe_display.pos_req_id_optional = function(value)
  return "Request ID: "..value
end

-- Dissect: Pos Req ID Optional
b3_entrypoint_sbe_dissect.pos_req_id_optional = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.pos_req_id_optional
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.pos_req_id_optional(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.pos_req_id_optional, range, value, display)

  return offset + length, value
end

-- Calculate size of: Position Maintenance Report Message
b3_entrypoint_sbe_size_of.position_maintenance_report_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.outbound_business_header

  index = index + b3_entrypoint_sbe_size_of.pos_req_id_optional

  index = index + b3_entrypoint_sbe_size_of.security_id

  index = index + b3_entrypoint_sbe_size_of.pos_maint_rpt_id

  index = index + b3_entrypoint_sbe_size_of.pos_trans_type

  index = index + b3_entrypoint_sbe_size_of.pos_maint_action

  index = index + b3_entrypoint_sbe_size_of.pos_maint_status

  index = index + b3_entrypoint_sbe_size_of.trade_id_optional

  index = index + b3_entrypoint_sbe_size_of.orig_pos_req_ref_id

  index = index + b3_entrypoint_sbe_size_of.account_type

  index = index + b3_entrypoint_sbe_size_of.clearing_business_date

  index = index + b3_entrypoint_sbe_size_of.threshold_amount

  index = index + b3_entrypoint_sbe_size_of.transact_time

  index = index + b3_entrypoint_sbe_size_of.account

  index = index + b3_entrypoint_sbe_size_of.sender_location

  index = index + b3_entrypoint_sbe_size_of.pos_maint_result

  index = index + b3_entrypoint_sbe_size_of.contrary_instruction_indicator

  return index
end

-- Display: Position Maintenance Report Message
b3_entrypoint_sbe_display.position_maintenance_report_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Position Maintenance Report Message
b3_entrypoint_sbe_dissect.position_maintenance_report_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Outbound Business Header: 1 Byte Ascii String
  index, outbound_business_header = b3_entrypoint_sbe_dissect.outbound_business_header(buffer, index, packet, parent)

  -- Pos Req ID Optional: 8 Byte Unsigned Fixed Width Integer
  index, pos_req_id_optional = b3_entrypoint_sbe_dissect.pos_req_id_optional(buffer, index, packet, parent)

  -- Security ID: 8 Byte Unsigned Fixed Width Integer
  index, security_id = b3_entrypoint_sbe_dissect.security_id(buffer, index, packet, parent)

  -- Pos Maint Rpt ID: 8 Byte Unsigned Fixed Width Integer
  index, pos_maint_rpt_id = b3_entrypoint_sbe_dissect.pos_maint_rpt_id(buffer, index, packet, parent)

  -- Pos Trans Type: 1 Byte Unsigned Fixed Width Integer Enum with 3 values
  index, pos_trans_type = b3_entrypoint_sbe_dissect.pos_trans_type(buffer, index, packet, parent)

  -- Pos Maint Action: 1 Byte Ascii String Enum with 2 values
  index, pos_maint_action = b3_entrypoint_sbe_dissect.pos_maint_action(buffer, index, packet, parent)

  -- Pos Maint Status: 1 Byte Ascii String Enum with 4 values
  index, pos_maint_status = b3_entrypoint_sbe_dissect.pos_maint_status(buffer, index, packet, parent)

  -- Trade ID Optional: 4 Byte Unsigned Fixed Width Integer
  index, trade_id_optional = b3_entrypoint_sbe_dissect.trade_id_optional(buffer, index, packet, parent)

  -- Orig Pos Req Ref ID: 8 Byte Unsigned Fixed Width Integer
  index, orig_pos_req_ref_id = b3_entrypoint_sbe_dissect.orig_pos_req_ref_id(buffer, index, packet, parent)

  -- Account Type: 1 Byte Unsigned Fixed Width Integer Enum with 3 values
  index, account_type = b3_entrypoint_sbe_dissect.account_type(buffer, index, packet, parent)

  -- Clearing Business Date: 2 Byte Unsigned Fixed Width Integer
  index, clearing_business_date = b3_entrypoint_sbe_dissect.clearing_business_date(buffer, index, packet, parent)

  -- Threshold Amount: 8 Byte Signed Fixed Width Integer Nullable
  index, threshold_amount = b3_entrypoint_sbe_dissect.threshold_amount(buffer, index, packet, parent)

  -- Transact Time: 8 Byte Unsigned Fixed Width Integer
  index, transact_time = b3_entrypoint_sbe_dissect.transact_time(buffer, index, packet, parent)

  -- Account: 4 Byte Unsigned Fixed Width Integer
  index, account = b3_entrypoint_sbe_dissect.account(buffer, index, packet, parent)

  -- Sender Location: 10 Byte Ascii String
  index, sender_location = b3_entrypoint_sbe_dissect.sender_location(buffer, index, packet, parent)

  -- Pos Maint Result: 4 Byte Unsigned Fixed Width Integer
  index, pos_maint_result = b3_entrypoint_sbe_dissect.pos_maint_result(buffer, index, packet, parent)

  -- Contrary Instruction Indicator: 1 Byte Unsigned Fixed Width Integer Enum with 2 values
  index, contrary_instruction_indicator = b3_entrypoint_sbe_dissect.contrary_instruction_indicator(buffer, index, packet, parent)

  return index
end

-- Dissect: Position Maintenance Report Message
b3_entrypoint_sbe_dissect.position_maintenance_report_message = function(buffer, offset, packet, parent)
  -- Optionally add dynamic struct element to protocol tree
  if show.position_maintenance_report_message then
    local length = b3_entrypoint_sbe_size_of.position_maintenance_report_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.position_maintenance_report_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.position_maintenance_report_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.position_maintenance_report_message_fields(buffer, offset, packet, parent)
end

-- Size: Long Qty
b3_entrypoint_sbe_size_of.long_qty = 8

-- Display: Long Qty
b3_entrypoint_sbe_display.long_qty = function(value)
  return "Quantity: "..value
end

-- Dissect: Long Qty
b3_entrypoint_sbe_dissect.long_qty = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.long_qty
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.long_qty(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.long_qty, range, value, display)

  return offset + length, value
end

-- Size: Pos Req ID
b3_entrypoint_sbe_size_of.pos_req_id = 8

-- Display: Pos Req ID
b3_entrypoint_sbe_display.pos_req_id = function(value)
  return "Request ID: "..value
end

-- Dissect: Pos Req ID
b3_entrypoint_sbe_dissect.pos_req_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.pos_req_id
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.pos_req_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.pos_req_id, range, value, display)

  return offset + length, value
end

-- Calculate size of: Position Maintenance Request Message
b3_entrypoint_sbe_size_of.position_maintenance_request_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.inbound_business_header

  index = index + b3_entrypoint_sbe_size_of.pos_req_id

  index = index + b3_entrypoint_sbe_size_of.security_id

  index = index + b3_entrypoint_sbe_size_of.threshold_amount

  index = index + b3_entrypoint_sbe_size_of.account

  index = index + b3_entrypoint_sbe_size_of.sender_location

  index = index + b3_entrypoint_sbe_size_of.pos_trans_type

  index = index + b3_entrypoint_sbe_size_of.clearing_business_date

  index = index + b3_entrypoint_sbe_size_of.contrary_instruction_indicator

  index = index + b3_entrypoint_sbe_size_of.entering_trader

  index = index + b3_entrypoint_sbe_size_of.long_qty

  return index
end

-- Display: Position Maintenance Request Message
b3_entrypoint_sbe_display.position_maintenance_request_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Position Maintenance Request Message
b3_entrypoint_sbe_dissect.position_maintenance_request_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Inbound Business Header: 1 Byte Ascii String
  index, inbound_business_header = b3_entrypoint_sbe_dissect.inbound_business_header(buffer, index, packet, parent)

  -- Pos Req ID: 8 Byte Unsigned Fixed Width Integer
  index, pos_req_id = b3_entrypoint_sbe_dissect.pos_req_id(buffer, index, packet, parent)

  -- Security ID: 8 Byte Unsigned Fixed Width Integer
  index, security_id = b3_entrypoint_sbe_dissect.security_id(buffer, index, packet, parent)

  -- Threshold Amount: 8 Byte Signed Fixed Width Integer Nullable
  index, threshold_amount = b3_entrypoint_sbe_dissect.threshold_amount(buffer, index, packet, parent)

  -- Account: 4 Byte Unsigned Fixed Width Integer
  index, account = b3_entrypoint_sbe_dissect.account(buffer, index, packet, parent)

  -- Sender Location: 10 Byte Ascii String
  index, sender_location = b3_entrypoint_sbe_dissect.sender_location(buffer, index, packet, parent)

  -- Pos Trans Type: 1 Byte Unsigned Fixed Width Integer Enum with 3 values
  index, pos_trans_type = b3_entrypoint_sbe_dissect.pos_trans_type(buffer, index, packet, parent)

  -- Clearing Business Date: 2 Byte Unsigned Fixed Width Integer
  index, clearing_business_date = b3_entrypoint_sbe_dissect.clearing_business_date(buffer, index, packet, parent)

  -- Contrary Instruction Indicator: 1 Byte Unsigned Fixed Width Integer Enum with 2 values
  index, contrary_instruction_indicator = b3_entrypoint_sbe_dissect.contrary_instruction_indicator(buffer, index, packet, parent)

  -- Entering Trader: 5 Byte Ascii String
  index, entering_trader = b3_entrypoint_sbe_dissect.entering_trader(buffer, index, packet, parent)

  -- Long Qty: 8 Byte Unsigned Fixed Width Integer
  index, long_qty = b3_entrypoint_sbe_dissect.long_qty(buffer, index, packet, parent)

  -- Desk ID: Struct of 2 fields
  index, desk_id = b3_entrypoint_sbe_dissect.desk_id(buffer, index, packet, parent)

  -- Memo: Struct of 2 fields
  index, memo = b3_entrypoint_sbe_dissect.memo(buffer, index, packet, parent)

  return index
end

-- Dissect: Position Maintenance Request Message
b3_entrypoint_sbe_dissect.position_maintenance_request_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.position_maintenance_request_message then
    local length = b3_entrypoint_sbe_size_of.position_maintenance_request_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.position_maintenance_request_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.position_maintenance_request_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.position_maintenance_request_message_fields(buffer, offset, packet, parent)
end

-- Size: Pos Maint Rpt Ref ID
b3_entrypoint_sbe_size_of.pos_maint_rpt_ref_id = 8

-- Display: Pos Maint Rpt Ref ID
b3_entrypoint_sbe_display.pos_maint_rpt_ref_id = function(value)
  return "RPT Reference ID: "..value
end

-- Dissect: Pos Maint Rpt Ref ID
b3_entrypoint_sbe_dissect.pos_maint_rpt_ref_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.pos_maint_rpt_ref_id
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.pos_maint_rpt_ref_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.pos_maint_rpt_ref_id, range, value, display)

  return offset + length, value
end

-- Calculate size of: Position Maintenance Cancel Request Message
b3_entrypoint_sbe_size_of.position_maintenance_cancel_request_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.inbound_business_header

  index = index + b3_entrypoint_sbe_size_of.pos_req_id

  index = index + b3_entrypoint_sbe_size_of.security_id

  index = index + b3_entrypoint_sbe_size_of.security_exchange

  index = index + b3_entrypoint_sbe_size_of.orig_pos_req_ref_id

  index = index + b3_entrypoint_sbe_size_of.pos_maint_rpt_ref_id

  index = index + b3_entrypoint_sbe_size_of.sender_location

  index = index + b3_entrypoint_sbe_size_of.entering_trader

  return index
end

-- Display: Position Maintenance Cancel Request Message
b3_entrypoint_sbe_display.position_maintenance_cancel_request_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Position Maintenance Cancel Request Message
b3_entrypoint_sbe_dissect.position_maintenance_cancel_request_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Inbound Business Header: 1 Byte Ascii String
  index, inbound_business_header = b3_entrypoint_sbe_dissect.inbound_business_header(buffer, index, packet, parent)

  -- Pos Req ID: 8 Byte Unsigned Fixed Width Integer
  index, pos_req_id = b3_entrypoint_sbe_dissect.pos_req_id(buffer, index, packet, parent)

  -- Security ID: 8 Byte Unsigned Fixed Width Integer
  index, security_id = b3_entrypoint_sbe_dissect.security_id(buffer, index, packet, parent)

  -- Orig Pos Req Ref ID: 8 Byte Unsigned Fixed Width Integer
  index, orig_pos_req_ref_id = b3_entrypoint_sbe_dissect.orig_pos_req_ref_id(buffer, index, packet, parent)

  -- Pos Maint Rpt Ref ID: 8 Byte Unsigned Fixed Width Integer
  index, pos_maint_rpt_ref_id = b3_entrypoint_sbe_dissect.pos_maint_rpt_ref_id(buffer, index, packet, parent)

  -- Sender Location: 10 Byte Ascii String
  index, sender_location = b3_entrypoint_sbe_dissect.sender_location(buffer, index, packet, parent)

  -- Entering Trader: 5 Byte Ascii String
  index, entering_trader = b3_entrypoint_sbe_dissect.entering_trader(buffer, index, packet, parent)

  return index
end

-- Dissect: Position Maintenance Cancel Request Message
b3_entrypoint_sbe_dissect.position_maintenance_cancel_request_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.position_maintenance_cancel_request_message then
    local length = b3_entrypoint_sbe_size_of.position_maintenance_cancel_request_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.position_maintenance_cancel_request_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.position_maintenance_cancel_request_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.position_maintenance_cancel_request_message_fields(buffer, offset, packet, parent)
end

-- Display: Var Data
b3_entrypoint_sbe_display.var_data = function(value)
  return "Var data: "..value
end

-- Dissect runtime sized field: Var Data
b3_entrypoint_sbe_dissect.var_data = function(buffer, offset, packet, parent, size)
  local range = buffer(offset, size)
  local value = range:bytes():tohex(false, " ")
  local display = b3_entrypoint_sbe_display.var_data(value, buffer, offset, packet, parent, size)

  parent:add(b3_entrypoint_sbe.fields.var_data, range, value, display)

  return offset + size
end

-- Calculate size of: Quote Req ID
b3_entrypoint_sbe_size_of.quote_req_id = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.length

  -- Parse runtime size of: Var Data
  index = index + buffer(offset + index - 1, 1):le_uint()

  return index
end

-- Display: Quote Req ID
b3_entrypoint_sbe_display.quote_req_id = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Quote Req ID
b3_entrypoint_sbe_dissect.quote_req_id_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Length: 1 Byte Unsigned Fixed Width Integer
  index, length = b3_entrypoint_sbe_dissect.length(buffer, index, packet, parent)

  -- Var Data: 0 Byte
  index = b3_entrypoint_sbe_dissect.var_data(buffer, index, packet, parent, length)

  return index
end

-- Dissect: Quote Req ID
b3_entrypoint_sbe_dissect.quote_req_id = function(buffer, offset, packet, parent)
  -- Optionally add dynamic struct element to protocol tree
  if show.quote_req_id then
    local length = b3_entrypoint_sbe_size_of.quote_req_id(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.quote_req_id(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.quote_req_id, range, display)
  end

  return b3_entrypoint_sbe_dissect.quote_req_id_fields(buffer, offset, packet, parent)
end

-- Size: Entering Firm Optional
b3_entrypoint_sbe_size_of.entering_firm_optional = 4

-- Display: Entering Firm Optional
b3_entrypoint_sbe_display.entering_firm_optional = function(value)
  return "Entering firm: "..value
end

-- Dissect: Entering Firm Optional
b3_entrypoint_sbe_dissect.entering_firm_optional = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.entering_firm_optional
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.entering_firm_optional(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.entering_firm_optional, range, value, display)

  return offset + length, value
end

-- Calculate size of: No Sides Group
b3_entrypoint_sbe_size_of.no_sides_group = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.side

  -- Padding 1 Byte
  index = index + 1

  index = index + b3_entrypoint_sbe_size_of.account

  index = index + b3_entrypoint_sbe_size_of.entering_firm_optional

  index = index + b3_entrypoint_sbe_size_of.clordid

  return index
end

-- Display: No Sides Group
b3_entrypoint_sbe_display.no_sides_group = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: No Sides Group
b3_entrypoint_sbe_dissect.no_sides_group_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Side: 1 Byte Ascii String Enum with 2 values
  index, side = b3_entrypoint_sbe_dissect.side(buffer, index, packet, parent)

  -- Padding: 1 Byte
  index = index + 1

  -- Account: 4 Byte Unsigned Fixed Width Integer
  index, account = b3_entrypoint_sbe_dissect.account(buffer, index, packet, parent)

  -- Entering Firm Optional: 4 Byte Unsigned Fixed Width Integer
  index, entering_firm_optional = b3_entrypoint_sbe_dissect.entering_firm_optional(buffer, index, packet, parent)

  -- ClOrdId: 8 Byte Unsigned Fixed Width Integer
  index, clordid = b3_entrypoint_sbe_dissect.clordid(buffer, index, packet, parent)

  return index
end

-- Dissect: No Sides Group
b3_entrypoint_sbe_dissect.no_sides_group = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.no_sides_group then
    local length = b3_entrypoint_sbe_size_of.no_sides_group(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.no_sides_group(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.no_sides_group, range, display)
  end

  return b3_entrypoint_sbe_dissect.no_sides_group_fields(buffer, offset, packet, parent)
end

-- Calculate size of: No Sides Groups
b3_entrypoint_sbe_size_of.no_sides_groups = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.group_size_encoding(buffer, offset + index)

  -- Calculate field size from count
  local no_sides_group_count = buffer(offset + index - 1, 1):le_uint()
  index = index + no_sides_group_count * 17

  return index
end

-- Display: No Sides Groups
b3_entrypoint_sbe_display.no_sides_groups = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: No Sides Groups
b3_entrypoint_sbe_dissect.no_sides_groups_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Group Size Encoding: Struct of 2 fields
  index, group_size_encoding = b3_entrypoint_sbe_dissect.group_size_encoding(buffer, index, packet, parent)

  -- Dependency element: Num In Group
  local num_in_group = buffer(index - 1, 1):le_uint()

  -- No Sides Group: Struct of 4 fields
  for i = 1, num_in_group do
    index = b3_entrypoint_sbe_dissect.no_sides_group(buffer, index, packet, parent)
  end

  return index
end

-- Dissect: No Sides Groups
b3_entrypoint_sbe_dissect.no_sides_groups = function(buffer, offset, packet, parent)
  -- Optionally add dynamic struct element to protocol tree
  if show.no_sides_groups then
    local length = b3_entrypoint_sbe_size_of.no_sides_groups(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.no_sides_groups(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.no_sides_groups, range, display)
  end

  return b3_entrypoint_sbe_dissect.no_sides_groups_fields(buffer, offset, packet, parent)
end

-- Size: Days To Settlement Optional
b3_entrypoint_sbe_size_of.days_to_settlement_optional = 2

-- Display: Days To Settlement Optional
b3_entrypoint_sbe_display.days_to_settlement_optional = function(value)
  return "Days to settlement: "..value
end

-- Dissect: Days To Settlement Optional
b3_entrypoint_sbe_dissect.days_to_settlement_optional = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.days_to_settlement_optional
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.days_to_settlement_optional(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.days_to_settlement_optional, range, value, display)

  return offset + length, value
end

-- Size: Fixed Rate Optional
b3_entrypoint_sbe_size_of.fixed_rate_optional = 8

-- Display: Fixed Rate Optional
b3_entrypoint_sbe_display.fixed_rate_optional = function(raw, value)
  -- Check null sentinel value
  if raw == Int64(0x00000000, 0x80000000) then
    return "Fixed rate: NULL"
  end

  return "Fixed rate: "..value
end

-- Translate: Fixed Rate Optional
translate.fixed_rate_optional = function(raw)
  -- Check null sentinel value
  if raw == Int64(0x00000000, 0x80000000) then
    return 0/0
  end

  return raw:tonumber()/10000
end

-- Dissect: Fixed Rate Optional
b3_entrypoint_sbe_dissect.fixed_rate_optional = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.fixed_rate_optional
  local range = buffer(offset, length)
  local raw = range:le_int64()
  local value = translate.fixed_rate_optional(raw)
  local display = b3_entrypoint_sbe_display.fixed_rate_optional(raw, value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.fixed_rate_optional, range, value, display)

  return offset + length, value
end

-- Size: Executing Trader
b3_entrypoint_sbe_size_of.executing_trader = 5

-- Display: Executing Trader
b3_entrypoint_sbe_display.executing_trader = function(value)
  -- Check if field has value
  if value == nil or value == '' then
    return "Executing trade: NULL"
  end

  return "Executing trader: "..value
end

-- Dissect: Executing Trader
b3_entrypoint_sbe_dissect.executing_trader = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.executing_trader
  local range = buffer(offset, length)

  -- parse last octet
  local last = buffer(offset + length - 1, 1):uint()

  -- read full string or up to first zero
  local value = ''
  if last == 0 then
    value = range:stringz()
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.executing_trader(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.executing_trader, range, value, display)

  return offset + length, value
end

-- Size: Order Qty Optional
b3_entrypoint_sbe_size_of.order_qty_optional = 8

-- Display: Order Qty Optional
b3_entrypoint_sbe_display.order_qty_optional = function(value)
  return "Order quantity: "..value
end

-- Dissect: Order Qty Optional
b3_entrypoint_sbe_dissect.order_qty_optional = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.order_qty_optional
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.order_qty_optional(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.order_qty_optional, range, value, display)

  return offset + length, value
end

-- Size: Price Optional
b3_entrypoint_sbe_size_of.price_optional = 8

-- Display: Price Optional
b3_entrypoint_sbe_display.price_optional = function(raw, value)
  -- Check null sentinel value
  if raw == Int64(0x00000000, 0x80000000) then
    return "Price: NULL"
  end

  return "Price: "..value
end

-- Translate: Price Optional
translate.price_optional = function(raw)
  -- Check null sentinel value
  if raw == Int64(0x00000000, 0x80000000) then
    return 0/0
  end

  return raw:tonumber()/10000
end

-- Dissect: Price Optional
b3_entrypoint_sbe_dissect.price_optional = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.price_optional
  local range = buffer(offset, length)
  local raw = range:le_int64()
  local value = translate.price_optional(raw)
  local display = b3_entrypoint_sbe_display.price_optional(raw, value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.price_optional, range, value, display)

  return offset + length, value
end

-- Size: SettlType Optional
b3_entrypoint_sbe_size_of.settltype_optional = 1

-- Display: SettlType Optional
b3_entrypoint_sbe_display.settltype_optional = function(value)
  if value == "0" then
    return "Settlement type: BUYERS_DISCRETION"
  end
  if value == "8" then
    return "Settlement type: SELLERS_DISCRETION"
  end
  if value == "X" then
    return "Settlement type: MUTUAL"
  end
  if value == 0 then
    return "Settlement type: NULL"
  end

  return "Settlement type: UNKNOWN("..value..")"
end

-- Dissect: SettlType Optional
b3_entrypoint_sbe_dissect.settltype_optional = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.settltype_optional
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()

  -- check if value is non zero
  if value == 0 then
    value = ''
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.settltype_optional(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.settltype_optional, range, value, display)

  return offset + length, value
end

-- Size: Contra Broker
b3_entrypoint_sbe_size_of.contra_broker = 4

-- Display: Contra Broker
b3_entrypoint_sbe_display.contra_broker = function(value)
  return "Contra broker: "..value
end

-- Dissect: Contra Broker
b3_entrypoint_sbe_dissect.contra_broker = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.contra_broker
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.contra_broker(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.contra_broker, range, value, display)

  return offset + length, value
end

-- Size: Quote ID Optional
b3_entrypoint_sbe_size_of.quote_id_optional = 8

-- Display: Quote ID Optional
b3_entrypoint_sbe_display.quote_id_optional = function(value)
  return "Quote ID: "..value
end

-- Dissect: Quote ID Optional
b3_entrypoint_sbe_dissect.quote_id_optional = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.quote_id_optional
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.quote_id_optional(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.quote_id_optional, range, value, display)

  return offset + length, value
end

-- Size: Quote Request Reject Reason
b3_entrypoint_sbe_size_of.quote_request_reject_reason = 4

-- Display: Quote Request Reject Reason
b3_entrypoint_sbe_display.quote_request_reject_reason = function(value)
  return "Quote request reject reason: "..value
end

-- Dissect: Quote Request Reject Reason
b3_entrypoint_sbe_dissect.quote_request_reject_reason = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.quote_request_reject_reason
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.quote_request_reject_reason(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.quote_request_reject_reason, range, value, display)

  return offset + length, value
end

-- Size: Bidirectional Business Header
b3_entrypoint_sbe_size_of.bidirectional_business_header = 1

-- Display: Bidirectional Business Header
b3_entrypoint_sbe_display.bidirectional_business_header = function(value)
  -- Check if field has value
  if value == nil or value == '' then
    return "Bidirectional business header: NULL"
  end

  return "Bidirectional business header: "..value
end

-- Dissect: Bidirectional Business Header
b3_entrypoint_sbe_dissect.bidirectional_business_header = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.bidirectional_business_header
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()

  -- check if value is non zero
  if value == 0 then
    value = ''
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.bidirectional_business_header(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.bidirectional_business_header, range, value, display)

  return offset + length, value
end

-- Calculate size of: Quote Request Reject Message
b3_entrypoint_sbe_size_of.quote_request_reject_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.bidirectional_business_header

  index = index + b3_entrypoint_sbe_size_of.quote_request_reject_reason

  index = index + b3_entrypoint_sbe_size_of.security_id

  index = index + b3_entrypoint_sbe_size_of.quote_id_optional

  index = index + b3_entrypoint_sbe_size_of.trade_id_optional

  index = index + b3_entrypoint_sbe_size_of.contra_broker

  index = index + b3_entrypoint_sbe_size_of.transact_time

  index = index + b3_entrypoint_sbe_size_of.entering_trader

  index = index + b3_entrypoint_sbe_size_of.settltype_optional

  index = index + b3_entrypoint_sbe_size_of.price_optional

  index = index + b3_entrypoint_sbe_size_of.order_qty_optional

  index = index + b3_entrypoint_sbe_size_of.sender_location

  index = index + b3_entrypoint_sbe_size_of.executing_trader

  index = index + b3_entrypoint_sbe_size_of.fixed_rate_optional

  index = index + b3_entrypoint_sbe_size_of.days_to_settlement_optional

  index = index + b3_entrypoint_sbe_size_of.no_sides_groups(buffer, offset + index)

  index = index + b3_entrypoint_sbe_size_of.quote_req_id(buffer, offset + index)

  return index
end

-- Display: Quote Request Reject Message
b3_entrypoint_sbe_display.quote_request_reject_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Quote Request Reject Message
b3_entrypoint_sbe_dissect.quote_request_reject_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Bidirectional Business Header: 1 Byte Ascii String
  index, bidirectional_business_header = b3_entrypoint_sbe_dissect.bidirectional_business_header(buffer, index, packet, parent)

  -- Quote Request Reject Reason: 4 Byte Unsigned Fixed Width Integer
  index, quote_request_reject_reason = b3_entrypoint_sbe_dissect.quote_request_reject_reason(buffer, index, packet, parent)

  -- Security ID: 8 Byte Unsigned Fixed Width Integer
  index, security_id = b3_entrypoint_sbe_dissect.security_id(buffer, index, packet, parent)

  -- Quote ID Optional: 8 Byte Unsigned Fixed Width Integer
  index, quote_id_optional = b3_entrypoint_sbe_dissect.quote_id_optional(buffer, index, packet, parent)

  -- Trade ID Optional: 4 Byte Unsigned Fixed Width Integer
  index, trade_id_optional = b3_entrypoint_sbe_dissect.trade_id_optional(buffer, index, packet, parent)

  -- Contra Broker: 4 Byte Unsigned Fixed Width Integer
  index, contra_broker = b3_entrypoint_sbe_dissect.contra_broker(buffer, index, packet, parent)

  -- Transact Time: 8 Byte Unsigned Fixed Width Integer
  index, transact_time = b3_entrypoint_sbe_dissect.transact_time(buffer, index, packet, parent)

  -- Entering Trader: 5 Byte Ascii String
  index, entering_trader = b3_entrypoint_sbe_dissect.entering_trader(buffer, index, packet, parent)

  -- SettlType Optional: 1 Byte Ascii String Enum with 4 values
  index, settltype_optional = b3_entrypoint_sbe_dissect.settltype_optional(buffer, index, packet, parent)

  -- Price Optional: 8 Byte Signed Fixed Width Integer Nullable
  index, price_optional = b3_entrypoint_sbe_dissect.price_optional(buffer, index, packet, parent)

  -- Order Qty Optional: 8 Byte Unsigned Fixed Width Integer
  index, order_qty_optional = b3_entrypoint_sbe_dissect.order_qty_optional(buffer, index, packet, parent)

  -- Sender Location: 10 Byte Ascii String
  index, sender_location = b3_entrypoint_sbe_dissect.sender_location(buffer, index, packet, parent)

  -- Executing Trader: 5 Byte Ascii String
  index, executing_trader = b3_entrypoint_sbe_dissect.executing_trader(buffer, index, packet, parent)

  -- Fixed Rate Optional: 8 Byte Signed Fixed Width Integer Nullable
  index, fixed_rate_optional = b3_entrypoint_sbe_dissect.fixed_rate_optional(buffer, index, packet, parent)

  -- Days To Settlement Optional: 2 Byte Unsigned Fixed Width Integer
  index, days_to_settlement_optional = b3_entrypoint_sbe_dissect.days_to_settlement_optional(buffer, index, packet, parent)

  -- No Sides Groups: Struct of 2 fields
  index, no_sides_groups = b3_entrypoint_sbe_dissect.no_sides_groups(buffer, index, packet, parent)

  -- Quote Req ID: Struct of 2 fields
  index, quote_req_id = b3_entrypoint_sbe_dissect.quote_req_id(buffer, index, packet, parent)

  -- Desk ID: Struct of 2 fields
  index, desk_id = b3_entrypoint_sbe_dissect.desk_id(buffer, index, packet, parent)


  return index
end

-- Dissect: Quote Request Reject Message
b3_entrypoint_sbe_dissect.quote_request_reject_message = function(buffer, offset, packet, parent)
  -- Optionally add dynamic struct element to protocol tree
  if show.quote_request_reject_message then
    local length = b3_entrypoint_sbe_size_of.quote_request_reject_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.quote_request_reject_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.quote_request_reject_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.quote_request_reject_message_fields(buffer, offset, packet, parent)
end

-- Calculate size of: Quote Cancel Message
b3_entrypoint_sbe_size_of.quote_cancel_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.bidirectional_business_header

  index = index + b3_entrypoint_sbe_size_of.security_id

  index = index + b3_entrypoint_sbe_size_of.quote_id_optional

  index = index + b3_entrypoint_sbe_size_of.account

  index = index + b3_entrypoint_sbe_size_of.sender_location

  index = index + b3_entrypoint_sbe_size_of.entering_trader

  index = index + b3_entrypoint_sbe_size_of.executing_trader

  index = index + b3_entrypoint_sbe_size_of.quote_req_id(buffer, offset + index)

  return index
end

-- Display: Quote Cancel Message
b3_entrypoint_sbe_display.quote_cancel_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Quote Cancel Message
b3_entrypoint_sbe_dissect.quote_cancel_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Bidirectional Business Header: 1 Byte Ascii String
  index, bidirectional_business_header = b3_entrypoint_sbe_dissect.bidirectional_business_header(buffer, index, packet, parent)

  -- Security ID: 8 Byte Unsigned Fixed Width Integer
  index, security_id = b3_entrypoint_sbe_dissect.security_id(buffer, index, packet, parent)

  -- Quote ID Optional: 8 Byte Unsigned Fixed Width Integer
  index, quote_id_optional = b3_entrypoint_sbe_dissect.quote_id_optional(buffer, index, packet, parent)

  -- Account: 4 Byte Unsigned Fixed Width Integer
  index, account = b3_entrypoint_sbe_dissect.account(buffer, index, packet, parent)

  -- Sender Location: 10 Byte Ascii String
  index, sender_location = b3_entrypoint_sbe_dissect.sender_location(buffer, index, packet, parent)

  -- Entering Trader: 5 Byte Ascii String
  index, entering_trader = b3_entrypoint_sbe_dissect.entering_trader(buffer, index, packet, parent)

  -- Executing Trader: 5 Byte Ascii String
  index, executing_trader = b3_entrypoint_sbe_dissect.executing_trader(buffer, index, packet, parent)

  -- Quote Req ID: Struct of 2 fields
  index, quote_req_id = b3_entrypoint_sbe_dissect.quote_req_id(buffer, index, packet, parent)


  return index
end

-- Dissect: Quote Cancel Message
b3_entrypoint_sbe_dissect.quote_cancel_message = function(buffer, offset, packet, parent)
  -- Optionally add dynamic struct element to protocol tree
  if show.quote_cancel_message then
    local length = b3_entrypoint_sbe_size_of.quote_cancel_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.quote_cancel_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.quote_cancel_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.quote_cancel_message_fields(buffer, offset, packet, parent)
end

-- Size: Days To Settlement
b3_entrypoint_sbe_size_of.days_to_settlement = 2

-- Display: Days To Settlement
b3_entrypoint_sbe_display.days_to_settlement = function(value)
  return "Days To Settlement: "..value
end

-- Dissect: Days To Settlement
b3_entrypoint_sbe_dissect.days_to_settlement = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.days_to_settlement
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.days_to_settlement(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.days_to_settlement, range, value, display)

  return offset + length, value
end

-- Size: Execute Underlying Trade
b3_entrypoint_sbe_size_of.execute_underlying_trade = 1

-- Display: Execute Underlying Trade
b3_entrypoint_sbe_display.execute_underlying_trade = function(value)
  if value == "0" then
    return "Execute underlying trade: NO_UNDERLYING_TRADE"
  end
  if value == "1" then
    return "Execute underlying trade: UNDERLYING_OPPOSING_TRADE"
  end
  if value == 0 then
    return "Execute underlying trade: NULL"
  end

  return "Execute underlying trade: UNKNOWN("..value..")"
end

-- Dissect: Execute Underlying Trade
b3_entrypoint_sbe_dissect.execute_underlying_trade = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.execute_underlying_trade
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()

  -- check if value is non zero
  if value == 0 then
    value = ''
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.execute_underlying_trade(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.execute_underlying_trade, range, value, display)

  return offset + length, value
end

-- Size: Fixed Rate
b3_entrypoint_sbe_size_of.fixed_rate = 8

-- Display: Fixed Rate
b3_entrypoint_sbe_display.fixed_rate = function(value)
  return "Fixed rate: "..value
end

-- Translate: Fixed Rate
translate.fixed_rate = function(raw)
  return raw:tonumber()/10000
end

-- Dissect: Fixed Rate
b3_entrypoint_sbe_dissect.fixed_rate = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.fixed_rate
  local range = buffer(offset, length)
  local raw = range:le_int64()
  local value = translate.fixed_rate(raw)
  local display = b3_entrypoint_sbe_display.fixed_rate(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.fixed_rate, range, value, display)

  return offset + length, value
end

-- Size: SettlType
b3_entrypoint_sbe_size_of.settltype = 1

-- Display: SettlType
b3_entrypoint_sbe_display.settltype = function(value)
  if value == "0" then
    return "Settlement type: BUYERS_DISCRETION"
  end
  if value == "8" then
    return "Settlement type: SELLERS_DISCRETION"
  end
  if value == "X" then
    return "Settlement type: MUTUAL"
  end

  return "Settlement type: UNKNOWN("..value..")"
end

-- Dissect: SettlType
b3_entrypoint_sbe_dissect.settltype = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.settltype
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()

  -- check if value is non zero
  if value == 0 then
    value = ''
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.settltype(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.settltype, range, value, display)

  return offset + length, value
end

-- Size: Order Qty
b3_entrypoint_sbe_size_of.order_qty = 8

-- Display: Order Qty
b3_entrypoint_sbe_display.order_qty = function(value)
  -- Check if field has value
  if value == UInt64(0xFFFFFFFF, 0xFFFFFFFF) then
    return "Order quantity: NULL"
  end


  return "Order quantity: "..value
end

-- Dissect: Order Qty
b3_entrypoint_sbe_dissect.order_qty = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.order_qty
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.order_qty(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.order_qty, range, value, display)

  return offset + length, value
end

-- Size: Quote ID
b3_entrypoint_sbe_size_of.quote_id = 8

-- Display: Quote ID
b3_entrypoint_sbe_display.quote_id = function(value)
  return "Quote ID: "..value
end

-- Dissect: Quote ID
b3_entrypoint_sbe_dissect.quote_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.quote_id
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.quote_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.quote_id, range, value, display)

  return offset + length, value
end

-- Calculate size of: Quote Message
b3_entrypoint_sbe_size_of.quote_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.bidirectional_business_header

  index = index + b3_entrypoint_sbe_size_of.security_id

  index = index + b3_entrypoint_sbe_size_of.quote_id

  index = index + b3_entrypoint_sbe_size_of.transact_time

  index = index + b3_entrypoint_sbe_size_of.price_optional

  index = index + b3_entrypoint_sbe_size_of.order_qty

  index = index + b3_entrypoint_sbe_size_of.side

  index = index + b3_entrypoint_sbe_size_of.settltype

  index = index + b3_entrypoint_sbe_size_of.account

  index = index + b3_entrypoint_sbe_size_of.sender_location

  index = index + b3_entrypoint_sbe_size_of.entering_trader

  index = index + b3_entrypoint_sbe_size_of.executing_trader

  index = index + b3_entrypoint_sbe_size_of.fixed_rate

  index = index + b3_entrypoint_sbe_size_of.execute_underlying_trade

  index = index + b3_entrypoint_sbe_size_of.days_to_settlement

  index = index + b3_entrypoint_sbe_size_of.quote_req_id(buffer, offset + index)


  return index
end

-- Display: Quote Message
b3_entrypoint_sbe_display.quote_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Quote Message
b3_entrypoint_sbe_dissect.quote_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Bidirectional Business Header: 1 Byte Ascii String
  index, bidirectional_business_header = b3_entrypoint_sbe_dissect.bidirectional_business_header(buffer, index, packet, parent)

  -- Security ID: 8 Byte Unsigned Fixed Width Integer
  index, security_id = b3_entrypoint_sbe_dissect.security_id(buffer, index, packet, parent)

  -- Quote ID: 8 Byte Unsigned Fixed Width Integer
  index, quote_id = b3_entrypoint_sbe_dissect.quote_id(buffer, index, packet, parent)

  -- Transact Time: 8 Byte Unsigned Fixed Width Integer
  index, transact_time = b3_entrypoint_sbe_dissect.transact_time(buffer, index, packet, parent)

  -- Price Optional: 8 Byte Signed Fixed Width Integer Nullable
  index, price_optional = b3_entrypoint_sbe_dissect.price_optional(buffer, index, packet, parent)

  -- Order Qty: 8 Byte Unsigned Fixed Width Integer
  index, order_qty = b3_entrypoint_sbe_dissect.order_qty(buffer, index, packet, parent)

  -- Side: 1 Byte Ascii String Enum with 2 values
  index, side = b3_entrypoint_sbe_dissect.side(buffer, index, packet, parent)

  -- SettlType: 1 Byte Ascii String Enum with 3 values
  index, settltype = b3_entrypoint_sbe_dissect.settltype(buffer, index, packet, parent)

  -- Account: 4 Byte Unsigned Fixed Width Integer
  index, account = b3_entrypoint_sbe_dissect.account(buffer, index, packet, parent)

  -- Sender Location: 10 Byte Ascii String
  index, sender_location = b3_entrypoint_sbe_dissect.sender_location(buffer, index, packet, parent)

  -- Entering Trader: 5 Byte Ascii String
  index, entering_trader = b3_entrypoint_sbe_dissect.entering_trader(buffer, index, packet, parent)

  -- Executing Trader: 5 Byte Ascii String
  index, executing_trader = b3_entrypoint_sbe_dissect.executing_trader(buffer, index, packet, parent)

  -- Fixed Rate: 8 Byte Signed Fixed Width Integer
  index, fixed_rate = b3_entrypoint_sbe_dissect.fixed_rate(buffer, index, packet, parent)

  -- Execute Underlying Trade: 1 Byte Ascii String Enum with 3 values
  index, execute_underlying_trade = b3_entrypoint_sbe_dissect.execute_underlying_trade(buffer, index, packet, parent)

  -- Days To Settlement: 2 Byte Unsigned Fixed Width Integer
  index, days_to_settlement = b3_entrypoint_sbe_dissect.days_to_settlement(buffer, index, packet, parent)

  -- Quote Req ID: Struct of 2 fields
  index, quote_req_id = b3_entrypoint_sbe_dissect.quote_req_id(buffer, index, packet, parent)


  return index
end

-- Dissect: Quote Message
b3_entrypoint_sbe_dissect.quote_message = function(buffer, offset, packet, parent)
  -- Optionally add dynamic struct element to protocol tree
  if show.quote_message then
    local length = b3_entrypoint_sbe_size_of.quote_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.quote_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.quote_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.quote_message_fields(buffer, offset, packet, parent)
end

-- Size: Quote Status Response To
b3_entrypoint_sbe_size_of.quote_status_response_to = 1

-- Display: Quote Status Response To
b3_entrypoint_sbe_display.quote_status_response_to = function(value)
  if value == "0" then
    return "Quote status response to: QUOTE"
  end
  if value == "1" then
    return "Quote status response to: QUOTE_REQUEST"
  end
  if value == "2" then
    return "Quote status response to: QUOTE_CANCEL"
  end
  if value == "3" then
    return "Quote status response to: QUOTE_REQUEST_REJECT"
  end
  if value == 0 then
    return "Quote status response to: NULL"
  end

  return "Quote status response to: UNKNOWN("..value..")"
end

-- Dissect: Quote Status Response To
b3_entrypoint_sbe_dissect.quote_status_response_to = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.quote_status_response_to
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()

  -- check if value is non zero
  if value == 0 then
    value = ''
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.quote_status_response_to(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.quote_status_response_to, range, value, display)

  return offset + length, value
end

-- Size: Quote Status
b3_entrypoint_sbe_size_of.quote_status = 1

-- Display: Quote Status
b3_entrypoint_sbe_display.quote_status = function(value)
  if value == 7 then
    return "Quote status: EXPIRED"
  end
  if value == 0 then
    return "Quote status: ACCEPTED"
  end
  if value == 5 then
    return "Quote status: REJECTED"
  end
  if value == 9 then
    return "Quote status: QUOTE_NOT_FOUND"
  end
  if value == 10 then
    return "Quote status: PENDING"
  end
  if value == 11 then
    return "Quote status: PASS"
  end
  if value == 17 then
    return "Quote status: CANCELED"
  end

  return "Quote status: UNKNOWN("..value..")"
end

-- Dissect: Quote Status
b3_entrypoint_sbe_dissect.quote_status = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.quote_status
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.quote_status(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.quote_status, range, value, display)

  return offset + length, value
end

-- Size: Quote Reject Reason
b3_entrypoint_sbe_size_of.quote_reject_reason = 4

-- Display: Quote Reject Reason
b3_entrypoint_sbe_display.quote_reject_reason = function(value)
  return "Quote reject reason: "..value
end

-- Dissect: Quote Reject Reason
b3_entrypoint_sbe_dissect.quote_reject_reason = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.quote_reject_reason
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.quote_reject_reason(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.quote_reject_reason, range, value, display)

  return offset + length, value
end

-- Calculate size of: Quote Status Report Message
b3_entrypoint_sbe_size_of.quote_status_report_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.bidirectional_business_header

  index = index + b3_entrypoint_sbe_size_of.quote_reject_reason

  index = index + b3_entrypoint_sbe_size_of.security_id

  index = index + b3_entrypoint_sbe_size_of.quote_id

  index = index + b3_entrypoint_sbe_size_of.trade_id_optional

  index = index + b3_entrypoint_sbe_size_of.contra_broker

  index = index + b3_entrypoint_sbe_size_of.transact_time

  index = index + b3_entrypoint_sbe_size_of.quote_status

  index = index + b3_entrypoint_sbe_size_of.quote_status_response_to

  index = index + b3_entrypoint_sbe_size_of.account

  index = index + b3_entrypoint_sbe_size_of.side

  index = index + b3_entrypoint_sbe_size_of.settltype_optional

  index = index + b3_entrypoint_sbe_size_of.price_optional

  index = index + b3_entrypoint_sbe_size_of.order_qty

  index = index + b3_entrypoint_sbe_size_of.sender_location

  index = index + b3_entrypoint_sbe_size_of.entering_trader

  index = index + b3_entrypoint_sbe_size_of.executing_trader

  index = index + b3_entrypoint_sbe_size_of.fixed_rate_optional

  index = index + b3_entrypoint_sbe_size_of.execute_underlying_trade

  index = index + b3_entrypoint_sbe_size_of.days_to_settlement_optional

  index = index + b3_entrypoint_sbe_size_of.quote_req_id(buffer, offset + index)

  return index
end

-- Display: Quote Status Report Message
b3_entrypoint_sbe_display.quote_status_report_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Quote Status Report Message
b3_entrypoint_sbe_dissect.quote_status_report_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Bidirectional Business Header: 1 Byte Ascii String
  index, bidirectional_business_header = b3_entrypoint_sbe_dissect.bidirectional_business_header(buffer, index, packet, parent)

  -- Quote Reject Reason: 4 Byte Unsigned Fixed Width Integer
  index, quote_reject_reason = b3_entrypoint_sbe_dissect.quote_reject_reason(buffer, index, packet, parent)

  -- Security ID: 8 Byte Unsigned Fixed Width Integer
  index, security_id = b3_entrypoint_sbe_dissect.security_id(buffer, index, packet, parent)

  -- Quote ID: 8 Byte Unsigned Fixed Width Integer
  index, quote_id = b3_entrypoint_sbe_dissect.quote_id(buffer, index, packet, parent)

  -- Trade ID Optional: 4 Byte Unsigned Fixed Width Integer
  index, trade_id_optional = b3_entrypoint_sbe_dissect.trade_id_optional(buffer, index, packet, parent)

  -- Contra Broker: 4 Byte Unsigned Fixed Width Integer
  index, contra_broker = b3_entrypoint_sbe_dissect.contra_broker(buffer, index, packet, parent)

  -- Transact Time: 8 Byte Unsigned Fixed Width Integer
  index, transact_time = b3_entrypoint_sbe_dissect.transact_time(buffer, index, packet, parent)

  -- Quote Status: 1 Byte Unsigned Fixed Width Integer Enum with 7 values
  index, quote_status = b3_entrypoint_sbe_dissect.quote_status(buffer, index, packet, parent)

  -- Quote Status Response To: 1 Byte Ascii String Enum with 5 values
  index, quote_status_response_to = b3_entrypoint_sbe_dissect.quote_status_response_to(buffer, index, packet, parent)

  -- Account: 4 Byte Unsigned Fixed Width Integer
  index, account = b3_entrypoint_sbe_dissect.account(buffer, index, packet, parent)

  -- Side Optional: 1 Byte Ascii String Enum with 3 values
  index, side = b3_entrypoint_sbe_dissect.side_optional(buffer, index, packet, parent)

  -- SettlType Optional: 1 Byte Ascii String Enum with 4 values
  index, settltype_optional = b3_entrypoint_sbe_dissect.settltype_optional(buffer, index, packet, parent)

  -- Price Optional: 8 Byte Signed Fixed Width Integer Nullable
  index, price_optional = b3_entrypoint_sbe_dissect.price_optional(buffer, index, packet, parent)

  -- Order Qty: 8 Byte Unsigned Fixed Width Integer
  index, order_qty = b3_entrypoint_sbe_dissect.order_qty(buffer, index, packet, parent)

  -- Sender Location: 10 Byte Ascii String
  index, sender_location = b3_entrypoint_sbe_dissect.sender_location(buffer, index, packet, parent)

  -- Entering Trader: 5 Byte Ascii String
  index, entering_trader = b3_entrypoint_sbe_dissect.entering_trader(buffer, index, packet, parent)

  -- Executing Trader: 5 Byte Ascii String
  index, executing_trader = b3_entrypoint_sbe_dissect.executing_trader(buffer, index, packet, parent)

  -- Fixed Rate Optional: 8 Byte Signed Fixed Width Integer Nullable
  index, fixed_rate_optional = b3_entrypoint_sbe_dissect.fixed_rate_optional(buffer, index, packet, parent)

  -- Execute Underlying Trade: 1 Byte Ascii String Enum with 3 values
  index, execute_underlying_trade = b3_entrypoint_sbe_dissect.execute_underlying_trade(buffer, index, packet, parent)

  -- Days To Settlement Optional: 2 Byte Unsigned Fixed Width Integer
  index, days_to_settlement_optional = b3_entrypoint_sbe_dissect.days_to_settlement_optional(buffer, index, packet, parent)

  -- Quote Req ID: Struct of 2 fields
  index, quote_req_id = b3_entrypoint_sbe_dissect.quote_req_id(buffer, index, packet, parent)

  return index
end

-- Dissect: Quote Status Report Message
b3_entrypoint_sbe_dissect.quote_status_report_message = function(buffer, offset, packet, parent)
  -- Optionally add dynamic struct element to protocol tree
  if show.quote_status_report_message then
    local length = b3_entrypoint_sbe_size_of.quote_status_report_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.quote_status_report_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.quote_status_report_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.quote_status_report_message_fields(buffer, offset, packet, parent)
end

-- Size: Price
b3_entrypoint_sbe_size_of.price = 8

-- Display: Price
b3_entrypoint_sbe_display.price = function(value)
  return "Price: "..value
end

-- Translate: Price
translate.price = function(raw)
  return raw:tonumber()/10000
end

-- Dissect: Price
b3_entrypoint_sbe_dissect.price = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.price
  local range = buffer(offset, length)
  local raw = range:le_int64()
  local value = translate.price(raw)
  local display = b3_entrypoint_sbe_display.price(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.price, range, value, display)

  return offset + length, value
end

-- Calculate size of: Quote Request Message
b3_entrypoint_sbe_size_of.quote_request_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.bidirectional_business_header

  index = index + b3_entrypoint_sbe_size_of.security_id

  index = index + b3_entrypoint_sbe_size_of.quote_id_optional

  index = index + b3_entrypoint_sbe_size_of.trade_id_optional

  index = index + b3_entrypoint_sbe_size_of.contra_broker

  index = index + b3_entrypoint_sbe_size_of.transact_time

  index = index + b3_entrypoint_sbe_size_of.price

  index = index + b3_entrypoint_sbe_size_of.settltype

  index = index + b3_entrypoint_sbe_size_of.execute_underlying_trade

  index = index + b3_entrypoint_sbe_size_of.order_qty

  index = index + b3_entrypoint_sbe_size_of.sender_location

  index = index + b3_entrypoint_sbe_size_of.entering_trader

  index = index + b3_entrypoint_sbe_size_of.executing_trader

  index = index + b3_entrypoint_sbe_size_of.fixed_rate

  index = index + b3_entrypoint_sbe_size_of.days_to_settlement

  index = index + b3_entrypoint_sbe_size_of.no_sides_groups(buffer, offset + index)

  index = index + b3_entrypoint_sbe_size_of.quote_req_id(buffer, offset + index)


  return index
end

-- Display: Quote Request Message
b3_entrypoint_sbe_display.quote_request_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Quote Request Message
b3_entrypoint_sbe_dissect.quote_request_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Bidirectional Business Header: 1 Byte Ascii String
  index, bidirectional_business_header = b3_entrypoint_sbe_dissect.bidirectional_business_header(buffer, index, packet, parent)

  -- Security ID: 8 Byte Unsigned Fixed Width Integer
  index, security_id = b3_entrypoint_sbe_dissect.security_id(buffer, index, packet, parent)

  -- Quote ID Optional: 8 Byte Unsigned Fixed Width Integer
  index, quote_id_optional = b3_entrypoint_sbe_dissect.quote_id_optional(buffer, index, packet, parent)

  -- Trade ID Optional: 4 Byte Unsigned Fixed Width Integer
  index, trade_id_optional = b3_entrypoint_sbe_dissect.trade_id_optional(buffer, index, packet, parent)

  -- Contra Broker: 4 Byte Unsigned Fixed Width Integer
  index, contra_broker = b3_entrypoint_sbe_dissect.contra_broker(buffer, index, packet, parent)

  -- Transact Time: 8 Byte Unsigned Fixed Width Integer
  index, transact_time = b3_entrypoint_sbe_dissect.transact_time(buffer, index, packet, parent)

  -- Price: 8 Byte Signed Fixed Width Integer
  index, price = b3_entrypoint_sbe_dissect.price(buffer, index, packet, parent)

  -- SettlType: 1 Byte Ascii String Enum with 3 values
  index, settltype = b3_entrypoint_sbe_dissect.settltype(buffer, index, packet, parent)

  -- Execute Underlying Trade: 1 Byte Ascii String Enum with 3 values
  index, execute_underlying_trade = b3_entrypoint_sbe_dissect.execute_underlying_trade(buffer, index, packet, parent)

  -- Order Qty: 8 Byte Unsigned Fixed Width Integer
  index, order_qty = b3_entrypoint_sbe_dissect.order_qty(buffer, index, packet, parent)

  -- Sender Location: 10 Byte Ascii String
  index, sender_location = b3_entrypoint_sbe_dissect.sender_location(buffer, index, packet, parent)

  -- Entering Trader: 5 Byte Ascii String
  index, entering_trader = b3_entrypoint_sbe_dissect.entering_trader(buffer, index, packet, parent)

  -- Executing Trader: 5 Byte Ascii String
  index, executing_trader = b3_entrypoint_sbe_dissect.executing_trader(buffer, index, packet, parent)

  -- Fixed Rate: 8 Byte Signed Fixed Width Integer
  index, fixed_rate = b3_entrypoint_sbe_dissect.fixed_rate(buffer, index, packet, parent)

  -- Days To Settlement: 2 Byte Unsigned Fixed Width Integer
  index, days_to_settlement = b3_entrypoint_sbe_dissect.days_to_settlement(buffer, index, packet, parent)

  -- No Sides Groups: Struct of 2 fields
  index, no_sides_groups = b3_entrypoint_sbe_dissect.no_sides_groups(buffer, index, packet, parent)

  -- Quote Req ID: Struct of 2 fields
  index, quote_req_id = b3_entrypoint_sbe_dissect.quote_req_id(buffer, index, packet, parent)


  return index
end

-- Dissect: Quote Request Message
b3_entrypoint_sbe_dissect.quote_request_message = function(buffer, offset, packet, parent)
  -- Optionally add dynamic struct element to protocol tree
  if show.quote_request_message then
    local length = b3_entrypoint_sbe_size_of.quote_request_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.quote_request_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.quote_request_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.quote_request_message_fields(buffer, offset, packet, parent)
end

-- Size: Security Response ID
b3_entrypoint_sbe_size_of.security_response_id = 8

-- Display: Security Response ID
b3_entrypoint_sbe_display.security_response_id = function(value)
  return "Security response ID: "..value
end

-- Dissect: Security Response ID
b3_entrypoint_sbe_dissect.security_response_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.security_response_id
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.security_response_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.security_response_id, range, value, display)

  return offset + length, value
end

-- Size: Symbol
b3_entrypoint_sbe_size_of.symbol = 20

-- Display: Symbol
b3_entrypoint_sbe_display.symbol = function(value)
  -- Check if field has value
  if value == nil or value == '' then
    return "Symbol: NULL"
  end

  return "Symbol: "..value
end

-- Dissect: Symbol
b3_entrypoint_sbe_dissect.symbol = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.symbol
  local range = buffer(offset, length)

  -- parse last octet
  local last = buffer(offset + length - 1, 1):uint()

  -- read full string or up to first zero
  local value = ''
  if last == 0 then
    value = range:stringz()
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.symbol(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.symbol, range, value, display)

  return offset + length, value
end

-- Size: Security Strategy Type
b3_entrypoint_sbe_size_of.security_strategy_type = 3

-- Display: Security Strategy Type
b3_entrypoint_sbe_display.security_strategy_type = function(value)
  -- Check if field has value
  if value == nil or value == '' then
    return "Security strategy type: NULL"
  end

  return "Security strategy type: "..value
end

-- Dissect: Security Strategy Type
b3_entrypoint_sbe_dissect.security_strategy_type = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.security_strategy_type
  local range = buffer(offset, length)

  -- parse last octet
  local last = buffer(offset + length - 1, 1):uint()

  -- read full string or up to first zero
  local value = ''
  if last == 0 then
    value = range:stringz()
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.security_strategy_type(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.security_strategy_type, range, value, display)

  return offset + length, value
end

-- Size: Security Response Type
b3_entrypoint_sbe_size_of.security_response_type = 1

-- Display: Security Response Type
b3_entrypoint_sbe_display.security_response_type = function(value)
  if value == 1 then
    return "Security response type: ACCEPT_SECURITY_PROPOSAL_AS_IS"
  end
  if value == 2 then
    return "Security response type: ACCEPT_SECURITY_AS_PROPOSAL_WITH_REVISIONS"
  end
  if value == 5 then
    return "Security response type: REJECT_SECURITY_PROPOSAL"
  end

  return "Security response type: UNKNOWN("..value..")"
end

-- Dissect: Security Response Type
b3_entrypoint_sbe_dissect.security_response_type = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.security_response_type
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.security_response_type(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.security_response_type, range, value, display)

  return offset + length, value
end

-- Size: Security Req ID
b3_entrypoint_sbe_size_of.security_req_id = 8

-- Display: Security Req ID
b3_entrypoint_sbe_display.security_req_id = function(value)
  return "Security request ID: "..value
end

-- Dissect: Security Req ID
b3_entrypoint_sbe_dissect.security_req_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.security_req_id
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.security_req_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.security_req_id, range, value, display)

  return offset + length, value
end

-- Calculate size of: Security Definition Response Message
b3_entrypoint_sbe_size_of.security_definition_response_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.outbound_business_header

  index = index + b3_entrypoint_sbe_size_of.security_req_id

  index = index + b3_entrypoint_sbe_size_of.security_id

  index = index + b3_entrypoint_sbe_size_of.security_response_type

  index = index + b3_entrypoint_sbe_size_of.security_strategy_type

  index = index + b3_entrypoint_sbe_size_of.symbol

  index = index + b3_entrypoint_sbe_size_of.security_response_id

  index = index + b3_entrypoint_sbe_size_of.sender_location

  index = index + b3_entrypoint_sbe_size_of.entering_trader

  return index
end

-- Display: Security Definition Response Message
b3_entrypoint_sbe_display.security_definition_response_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Security Definition Response Message
b3_entrypoint_sbe_dissect.security_definition_response_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Outbound Business Header: 1 Byte Ascii String
  index, outbound_business_header = b3_entrypoint_sbe_dissect.outbound_business_header(buffer, index, packet, parent)

  -- Security Req ID: 8 Byte Unsigned Fixed Width Integer
  index, security_req_id = b3_entrypoint_sbe_dissect.security_req_id(buffer, index, packet, parent)

  -- Security ID: 8 Byte Unsigned Fixed Width Integer
  index, security_id = b3_entrypoint_sbe_dissect.security_id(buffer, index, packet, parent)

  -- Security Response Type: 1 Byte Unsigned Fixed Width Integer Enum with 3 values
  index, security_response_type = b3_entrypoint_sbe_dissect.security_response_type(buffer, index, packet, parent)

  -- Security Strategy Type: 3 Byte Ascii String
  index, security_strategy_type = b3_entrypoint_sbe_dissect.security_strategy_type(buffer, index, packet, parent)

  -- Symbol: 20 Byte Ascii String
  index, symbol = b3_entrypoint_sbe_dissect.symbol(buffer, index, packet, parent)

  -- Security Response ID: 8 Byte Unsigned Fixed Width Integer
  index, security_response_id = b3_entrypoint_sbe_dissect.security_response_id(buffer, index, packet, parent)

  -- Sender Location: 10 Byte Ascii String
  index, sender_location = b3_entrypoint_sbe_dissect.sender_location(buffer, index, packet, parent)

  -- Entering Trader: 5 Byte Ascii String
  index, entering_trader = b3_entrypoint_sbe_dissect.entering_trader(buffer, index, packet, parent)

  return index
end

-- Dissect: Security Definition Response Message
b3_entrypoint_sbe_dissect.security_definition_response_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.security_definition_response_message then
    local length = b3_entrypoint_sbe_size_of.security_definition_response_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.security_definition_response_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.security_definition_response_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.security_definition_response_message_fields(buffer, offset, packet, parent)
end

-- Size: Leg Side
b3_entrypoint_sbe_size_of.leg_side = 1

-- Display: Leg Side
b3_entrypoint_sbe_display.leg_side = function(value)
  if value == "1" then
    return "Leg side: BUY"
  end
  if value == "2" then
    return "Leg side: SELL"
  end
  if value == 0 then
    return "Leg side: NULL"
  end

  return "Leg Side: UNKNOWN("..value..")"
end

-- Dissect: Leg Side
b3_entrypoint_sbe_dissect.leg_side = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.leg_side
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()

  -- check if value is non zero
  if value == 0 then
    value = ''
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.leg_side(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.leg_side, range, value, display)

  return offset + length, value
end

-- Size: Leg Ratio Qty
b3_entrypoint_sbe_size_of.leg_ratio_qty = 8

-- Display: Leg Ratio Qty
b3_entrypoint_sbe_display.leg_ratio_qty = function(value)
  return "Leg ratio quantity: "..value
end

-- Translate: Leg Ratio Qty
translate.leg_ratio_qty = function(raw)
  return raw:tonumber()/10000000
end

-- Dissect: Leg Ratio Qty
b3_entrypoint_sbe_dissect.leg_ratio_qty = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.leg_ratio_qty
  local range = buffer(offset, length)
  local raw = range:le_int64()
  local value = translate.leg_ratio_qty(raw)
  local display = b3_entrypoint_sbe_display.leg_ratio_qty(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.leg_ratio_qty, range, value, display)

  return offset + length, value
end

-- Size: Leg Security Exchange
b3_entrypoint_sbe_size_of.leg_security_exchange = 4

-- Display: Leg Security Exchange
b3_entrypoint_sbe_display.leg_security_exchange = function(value)
  -- Check if field has value
  if value == nil or value == '' then
    return "Leg security exchange: NULL"
  end

  return "Leg security exchange: "..value
end

-- Dissect: Leg Security Exchange
b3_entrypoint_sbe_dissect.leg_security_exchange = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.leg_security_exchange
  local range = buffer(offset, length)

  -- parse last octet
  local last = buffer(offset + length - 1, 1):uint()

  -- read full string or up to first zero
  local value = ''
  if last == 0 then
    value = range:stringz()
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.leg_security_exchange(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.leg_security_exchange, range, value, display)

  return offset + length, value
end

-- Size: Leg Symbol
b3_entrypoint_sbe_size_of.leg_symbol = 20

-- Display: Leg Symbol
b3_entrypoint_sbe_display.leg_symbol = function(value)
  -- Check if field has value
  if value == nil or value == '' then
    return "Leg symbol: NULL"
  end

  return "Leg symbol: "..value
end

-- Dissect: Leg Symbol
b3_entrypoint_sbe_dissect.leg_symbol = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.leg_symbol
  local range = buffer(offset, length)

  -- parse last octet
  local last = buffer(offset + length - 1, 1):uint()

  -- read full string or up to first zero
  local value = ''
  if last == 0 then
    value = range:stringz()
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.leg_symbol(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.leg_symbol, range, value, display)

  return offset + length, value
end

-- Calculate size of: No Legs Group
b3_entrypoint_sbe_size_of.no_legs_group = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.leg_symbol

  index = index + b3_entrypoint_sbe_size_of.leg_security_exchange

  index = index + b3_entrypoint_sbe_size_of.leg_ratio_qty

  index = index + b3_entrypoint_sbe_size_of.leg_side

  return index
end

-- Display: No Legs Group
b3_entrypoint_sbe_display.no_legs_group = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: No Legs Group
b3_entrypoint_sbe_dissect.no_legs_group_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Leg Symbol: 20 Byte Ascii String
  index, leg_symbol = b3_entrypoint_sbe_dissect.leg_symbol(buffer, index, packet, parent)

  -- Leg Security Exchange: 4 Byte Ascii String
  index, leg_security_exchange = b3_entrypoint_sbe_dissect.leg_security_exchange(buffer, index, packet, parent)

  -- Leg Ratio Qty: 8 Byte Signed Fixed Width Integer
  index, leg_ratio_qty = b3_entrypoint_sbe_dissect.leg_ratio_qty(buffer, index, packet, parent)

  -- Leg Side: 1 Byte Ascii String Enum with 3 values
  index, leg_side = b3_entrypoint_sbe_dissect.leg_side(buffer, index, packet, parent)

  return index
end

-- Dissect: No Legs Group
b3_entrypoint_sbe_dissect.no_legs_group = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.no_legs_group then
    local length = b3_entrypoint_sbe_size_of.no_legs_group(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.no_legs_group(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.no_legs_group, range, display)
  end

  return b3_entrypoint_sbe_dissect.no_legs_group_fields(buffer, offset, packet, parent)
end

-- Calculate size of: No Legs Groups
b3_entrypoint_sbe_size_of.no_legs_groups = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.group_size_encoding(buffer, offset + index)

  -- Calculate field size from count
  local no_legs_group_count = buffer(offset + index - 1, 1):le_uint()
  index = index + no_legs_group_count * 33

  return index
end

-- Display: No Legs Groups
b3_entrypoint_sbe_display.no_legs_groups = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: No Legs Groups
b3_entrypoint_sbe_dissect.no_legs_groups_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Group Size Encoding: Struct of 2 fields
  index, group_size_encoding = b3_entrypoint_sbe_dissect.group_size_encoding(buffer, index, packet, parent)

  -- Dependency element: Num In Group
  local num_in_group = buffer(index - 1, 1):le_uint()

  -- No Legs Group: Struct of 4 fields
  for i = 1, num_in_group do
    index = b3_entrypoint_sbe_dissect.no_legs_group(buffer, index, packet, parent)
  end

  return index
end

-- Dissect: No Legs Groups
b3_entrypoint_sbe_dissect.no_legs_groups = function(buffer, offset, packet, parent)
  -- Optionally add dynamic struct element to protocol tree
  if show.no_legs_groups then
    local length = b3_entrypoint_sbe_size_of.no_legs_groups(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.no_legs_groups(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.no_legs_groups, range, display)
  end

  return b3_entrypoint_sbe_dissect.no_legs_groups_fields(buffer, offset, packet, parent)
end

-- Calculate size of: Security Definition Request Message
b3_entrypoint_sbe_size_of.security_definition_request_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.inbound_business_header

  index = index + b3_entrypoint_sbe_size_of.security_req_id

  index = index + b3_entrypoint_sbe_size_of.sender_location

  index = index + b3_entrypoint_sbe_size_of.entering_trader

  index = index + b3_entrypoint_sbe_size_of.no_legs_groups(buffer, offset + index)

  return index
end

-- Display: Security Definition Request Message
b3_entrypoint_sbe_display.security_definition_request_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Security Definition Request Message
b3_entrypoint_sbe_dissect.security_definition_request_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Inbound Business Header: 1 Byte Ascii String
  index, inbound_business_header = b3_entrypoint_sbe_dissect.inbound_business_header(buffer, index, packet, parent)

  -- Security Req ID: 8 Byte Unsigned Fixed Width Integer
  index, security_req_id = b3_entrypoint_sbe_dissect.security_req_id(buffer, index, packet, parent)

  -- Sender Location: 10 Byte Ascii String
  index, sender_location = b3_entrypoint_sbe_dissect.sender_location(buffer, index, packet, parent)

  -- Entering Trader: 5 Byte Ascii String
  index, entering_trader = b3_entrypoint_sbe_dissect.entering_trader(buffer, index, packet, parent)

  -- No Legs Groups: Struct of 2 fields
  index, no_legs_groups = b3_entrypoint_sbe_dissect.no_legs_groups(buffer, index, packet, parent)

  return index
end

-- Dissect: Security Definition Request Message
b3_entrypoint_sbe_dissect.security_definition_request_message = function(buffer, offset, packet, parent)
  -- Optionally add dynamic struct element to protocol tree
  if show.security_definition_request_message then
    local length = b3_entrypoint_sbe_size_of.security_definition_request_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.security_definition_request_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.security_definition_request_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.security_definition_request_message_fields(buffer, offset, packet, parent)
end

-- Size: Business Reject Reason
b3_entrypoint_sbe_size_of.business_reject_reason = 4

-- Display: Business Reject Reason
b3_entrypoint_sbe_display.business_reject_reason = function(value)
  return "Business reject reason: "..value
end

-- Dissect: Business Reject Reason
b3_entrypoint_sbe_dissect.business_reject_reason = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.business_reject_reason
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.business_reject_reason(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.business_reject_reason, range, value, display)

  return offset + length, value
end

-- Size: Business Reject Ref ID
b3_entrypoint_sbe_size_of.business_reject_ref_id = 8

-- Display: Business Reject Ref ID
b3_entrypoint_sbe_display.business_reject_ref_id = function(value)
  return "Business reject ref ID: "..value
end

-- Dissect: Business Reject Ref ID
b3_entrypoint_sbe_dissect.business_reject_ref_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.business_reject_ref_id
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.business_reject_ref_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.business_reject_ref_id, range, value, display)

  return offset + length, value
end

-- Size: Ref Seq Num
b3_entrypoint_sbe_size_of.ref_seq_num = 4

-- Display: Ref Seq Num
b3_entrypoint_sbe_display.ref_seq_num = function(value)
  return "Ref Seq Num: "..value
end

-- Dissect: Ref Seq Num
b3_entrypoint_sbe_dissect.ref_seq_num = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.ref_seq_num
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.ref_seq_num(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.ref_seq_num, range, value, display)

  return offset + length, value
end

-- Size: Ref Msg Type
b3_entrypoint_sbe_size_of.ref_msg_type = 1

-- Display: Ref Msg Type
b3_entrypoint_sbe_display.ref_msg_type = function(value)
  if value == 0 then
    return "Reference message type: NEGOTIATE"
  end
  if value == 1 then
    return "Reference message type: NEGOTIATE_RESPONSE"
  end
  if value == 2 then
    return "Reference message type: NEGOTIATE_REJECT"
  end
  if value == 3 then
    return "Reference message type: ESTABLISH"
  end
  if value == 4 then
    return "Reference message type: ESTABLISH_ACK"
  end
  if value == 5 then
    return "Reference message type: ESTABLISH_REJECT"
  end
  if value == 6 then
    return "Reference message type: TERMINATE"
  end
  if value == 9 then
    return "Reference message type: NOT_APPLIED"
  end
  if value == 10 then
    return "Reference message type: RETRANSMIT_REQUEST"
  end
  if value == 11 then
    return "Reference message type: RETRANSMISSION"
  end
  if value == 12 then
    return "Reference message type: RETRANSMIT_REJECT"
  end
  if value == 13 then
    return "Reference message type: SEQUENCE"
  end
  if value == 14 then
    return "Reference message type: BUSINESS_MESSAGE_REJECT"
  end
  if value == 15 then
    return "Reference message type: SIMPLE_NEW_ORDER"
  end
  if value == 16 then
    return "Reference message type: SIMPLE_MODIFY_ORDER"
  end
  if value == 17 then
    return "Reference message type: NEW_ORDER_SINGLE"
  end
  if value == 18 then
    return "Reference message type: ORDER_CANCEL_REPLACE_REQUEST"
  end
  if value == 19 then
    return "Reference message type: ORDER_CANCEL_REQUEST"
  end
  if value == 20 then
    return "Reference message type: NEW_ORDER_CROSS"
  end
  if value == 21 then
    return "Reference message type: EXECUTION_REPORT_NEW"
  end
  if value == 22 then
    return "Reference message type: EXECUTION_REPORT_MODIFY"
  end
  if value == 23 then
    return "Reference message type: EXECUTION_REPORT_CANCEL"
  end
  if value == 24 then
    return "Reference message type: EXECUTION_REPORT_TRADE"
  end
  if value == 25 then
    return "Reference message type: EXECUTION_REPORT_REJECT"
  end
  if value == 26 then
    return "Reference message type: EXECUTION_REPORT_FORWARD"
  end
  if value == 27 then
    return "Reference message type: SECURITY_DEFINITION_REQUEST"
  end
  if value == 28 then
    return "Reference message type: SECURITY_DEFINITION_RESPONSE"
  end
  if value == 29 then
    return "Reference message type: ORDER_MASS_ACTION_REQUEST"
  end
  if value == 30 then
    return "Reference message type: ORDER_MASS_ACTION_RESPONSE"
  end
  if value == 31 then
    return "Reference message type: QUOTE_REQUEST"
  end
  if value == 32 then
    return "Reference message type: QUOTE_STATUS_REPORT"
  end
  if value == 33 then
    return "Reference message type: QUOTE"
  end
  if value == 34 then
    return "Reference message type: QUOTE_CANCEL"
  end
  if value == 35 then
    return "Reference message type: QUOTE_REQUEST_REJECT"
  end
  if value == 36 then
    return "Reference message type: POSITION_MAINTENANCE_CANCEL_REQUEST"
  end
  if value == 37 then
    return "Reference message type: POSITION_MAINTENANCE_REQUEST"
  end
  if value == 38 then
    return "Reference message type: POSITION_MAINTENANCE_REPORT"
  end
  if value == 39 then
    return "Reference message type: ALLOCATION_INSTRUCTION"
  end
  if value == 40 then
    return "Reference message type: ALLOCATION_REPORT"
  end

  return "Reference message type: UNKNOWN("..value..")"
end

-- Dissect: Ref Msg Type
b3_entrypoint_sbe_dissect.ref_msg_type = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.ref_msg_type
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.ref_msg_type(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.ref_msg_type, range, value, display)

  return offset + length, value
end

-- Calculate size of: Business Message Reject
b3_entrypoint_sbe_size_of.business_message_reject = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.outbound_business_header

  index = index + b3_entrypoint_sbe_size_of.ref_msg_type

  -- Padding 1 Byte
  index = index + 1

  index = index + b3_entrypoint_sbe_size_of.ref_seq_num

  index = index + b3_entrypoint_sbe_size_of.business_reject_ref_id

  index = index + b3_entrypoint_sbe_size_of.business_reject_reason

  index = index + b3_entrypoint_sbe_size_of.memo(buffer, offset + index)

  index = index + b3_entrypoint_sbe_size_of.text(buffer, offset + index)

  return index
end

-- Display: Business Message Reject
b3_entrypoint_sbe_display.business_message_reject = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Business Message Reject
b3_entrypoint_sbe_dissect.business_message_reject_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Outbound Business Header: 1 Byte Ascii String
  index, outbound_business_header = b3_entrypoint_sbe_dissect.outbound_business_header(buffer, index, packet, parent)

  -- Ref Msg Type: 1 Byte Unsigned Fixed Width Integer Enum with 39 values
  index, ref_msg_type = b3_entrypoint_sbe_dissect.ref_msg_type(buffer, index, packet, parent)

  -- Padding 1 Byte
  index = index + 1

  -- Ref Seq Num: 4 Byte Unsigned Fixed Width Integer
  index, ref_seq_num = b3_entrypoint_sbe_dissect.ref_seq_num(buffer, index, packet, parent)

  -- Business Reject Ref ID: 8 Byte Unsigned Fixed Width Integer
  index, business_reject_ref_id = b3_entrypoint_sbe_dissect.business_reject_ref_id(buffer, index, packet, parent)

  -- Business Reject Reason: 4 Byte Unsigned Fixed Width Integer
  index, business_reject_reason = b3_entrypoint_sbe_dissect.business_reject_reason(buffer, index, packet, parent)

  -- Memo: 1 Byte (Length) + N Bytes
  index, memo = b3_entrypoint_sbe_dissect.memo(buffer, index, packet, parent)

  -- Text: 1 Byte (Length) + N Bytes
  index, text = b3_entrypoint_sbe_dissect.text(buffer, index, packet, parent)


  return index
end

-- Dissect: Business Message Reject
b3_entrypoint_sbe_dissect.business_message_reject = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.business_message_reject then
    local length = b3_entrypoint_sbe_size_of.business_message_reject(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.business_message_reject(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.business_message_reject, range, display)
  end

  return b3_entrypoint_sbe_dissect.business_message_reject_fields(buffer, offset, packet, parent)
end

-- Size: Exec Ref ID
b3_entrypoint_sbe_size_of.exec_ref_id = 8

-- Display: Exec Ref ID
b3_entrypoint_sbe_display.exec_ref_id = function(value)
  return "Exec ref ID: "..value
end

-- Dissect: Exec Ref ID
b3_entrypoint_sbe_dissect.exec_ref_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.exec_ref_id
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.exec_ref_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.exec_ref_id, range, value, display)

  return offset + length, value
end

-- Size: Secondary Exec ID
b3_entrypoint_sbe_size_of.secondary_exec_id = 8

-- Display: Secondary Exec ID
b3_entrypoint_sbe_display.secondary_exec_id = function(value)
  return "Secondary exec ID: "..value
end

-- Dissect: Secondary Exec ID
b3_entrypoint_sbe_dissect.secondary_exec_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.secondary_exec_id
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.secondary_exec_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.secondary_exec_id, range, value, display)

  return offset + length, value
end

-- Size: Trade Date
b3_entrypoint_sbe_size_of.trade_date = 2

-- Display: Trade Date
b3_entrypoint_sbe_display.trade_date = function(value)
  return "Trade date: "..value
end

-- Dissect: Trade Date
b3_entrypoint_sbe_dissect.trade_date = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.trade_date
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.trade_date(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.trade_date, range, value, display)

  return offset + length, value
end

-- Size: Aggressor Indicator
b3_entrypoint_sbe_size_of.aggressor_indicator = 1

-- Display: Aggressor Indicator
b3_entrypoint_sbe_display.aggressor_indicator = function(value)
  if value == 0 then
    return "Aggressor indicator: FALSE"
  end
  if value == 1 then
    return "Aggressor indicator: TRUE"
  end

  return "Aggressor Indicator: UNKNOWN("..value..")"
end

-- Dissect: Aggressor Indicator
b3_entrypoint_sbe_dissect.aggressor_indicator = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.aggressor_indicator
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.aggressor_indicator(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.aggressor_indicator, range, value, display)

  return offset + length, value
end

-- Size: Order ID
b3_entrypoint_sbe_size_of.order_id = 8

-- Display: Order ID
b3_entrypoint_sbe_display.order_id = function(value)
  return "Order ID: "..value
end

-- Dissect: Order ID
b3_entrypoint_sbe_dissect.order_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.order_id
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.order_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.order_id, range, value, display)

  return offset + length, value
end

-- Size: Cum Qty
b3_entrypoint_sbe_size_of.cum_qty = 8

-- Display: Cum Qty
b3_entrypoint_sbe_display.cum_qty = function(value)
  return "Cumulative quantity (shares filled): "..value
end

-- Dissect: Cum Qty
b3_entrypoint_sbe_dissect.cum_qty = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.cum_qty
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.cum_qty(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.cum_qty, range, value, display)

  return offset + length, value
end

-- Size: Leaves Qty
b3_entrypoint_sbe_size_of.leaves_qty = 8

-- Display: Leaves Qty
b3_entrypoint_sbe_display.leaves_qty = function(value)
  return "Leaves quantity: "..value
end

-- Dissect: Leaves Qty
b3_entrypoint_sbe_dissect.leaves_qty = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.leaves_qty
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.leaves_qty(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.leaves_qty, range, value, display)

  return offset + length, value
end

-- Size: Exec ID
b3_entrypoint_sbe_size_of.exec_id = 8

-- Display: Exec ID
b3_entrypoint_sbe_display.exec_id = function(value)
  return "Execution ID: "..value
end

-- Dissect: Exec ID
b3_entrypoint_sbe_dissect.exec_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.exec_id
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.exec_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.exec_id, range, value, display)

  return offset + length, value
end

-- Size: Last Px
b3_entrypoint_sbe_size_of.last_px = 8

-- Display: Last Px
b3_entrypoint_sbe_display.last_px = function(value)
  return "Last price "..value
end

-- Translate: Last Px
translate.last_px = function(raw)
  return raw:tonumber()/10000
end

-- Dissect: Last Px
b3_entrypoint_sbe_dissect.last_px = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.last_px
  local range = buffer(offset, length)
  local raw = range:le_int64()
  local value = translate.last_px(raw)
  local display = b3_entrypoint_sbe_display.last_px(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.last_px, range, value, display)

  return offset + length, value
end

-- Size: Last Qty
b3_entrypoint_sbe_size_of.last_qty = 8

-- Display: Last Qty
b3_entrypoint_sbe_display.last_qty = function(value)
  return "Last quantity: "..value
end

-- Dissect: Last Qty
b3_entrypoint_sbe_dissect.last_qty = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.last_qty
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.last_qty(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.last_qty, range, value, display)

  return offset + length, value
end

-- Size: Secondary Order ID
b3_entrypoint_sbe_size_of.secondary_order_id = 8

-- Display: Secondary Order ID
b3_entrypoint_sbe_display.secondary_order_id = function(value)
  return "Secondary order ID: "..value
end

-- Dissect: Secondary Order ID
b3_entrypoint_sbe_dissect.secondary_order_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.secondary_order_id
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.secondary_order_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.secondary_order_id, range, value, display)

  return offset + length, value
end

-- Size: ClOrdId Optional
b3_entrypoint_sbe_size_of.clordid_optional = 8

-- Display: ClOrdId Optional
b3_entrypoint_sbe_display.clordid_optional = function(value)
  return "Client order ID: "..value
end

-- Dissect: ClOrdId Optional
b3_entrypoint_sbe_dissect.clordid_optional = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.clordid_optional
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.clordid_optional(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.clordid_optional, range, value, display)

  return offset + length, value
end

-- Size: Ord Status
b3_entrypoint_sbe_size_of.ord_status = 1

-- Display: Ord Status
b3_entrypoint_sbe_display.ord_status = function(value)
  if value == 48 then
    return "Order status: NEW"
  end
  if value == 49 then
    return "Order status: PARTIALLY_FILLED"
  end
  if value == 50 then
    return "Order status: FILLED"
  end
  if value == 52 then
    return "Order status: CANCELED"
  end
  if value == 53 then
    return "Order status: REPLACED"
  end
  if value == 56 then
    return "Order status: REJECTED"
  end
  if value == 67 then
    return "Order status: EXPIRED"
  end
  if value == 82 then
    return "Order status: RESTATED"
  end
  if value == 90 then
    return "Order status: PREVIOUS_FINAL_STATE"
  end

  return "Ord Status: UNKNOWN("..value..")"
end

-- Dissect: Ord Status
b3_entrypoint_sbe_dissect.ord_status = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.ord_status
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()

  local display = b3_entrypoint_sbe_display.ord_status(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.ord_status, range, value, display)

  return offset + length, value
end

-- Calculate size of: Execution Report Forward Message
b3_entrypoint_sbe_size_of.execution_report_forward_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.outbound_business_header

  index = index + b3_entrypoint_sbe_size_of.side

  index = index + b3_entrypoint_sbe_size_of.ord_status

  index = index + b3_entrypoint_sbe_size_of.clordid_optional

  index = index + b3_entrypoint_sbe_size_of.secondary_order_id

  index = index + b3_entrypoint_sbe_size_of.security_id

  index = index + b3_entrypoint_sbe_size_of.security_exchange

  index = index + b3_entrypoint_sbe_size_of.account

  index = index + b3_entrypoint_sbe_size_of.last_qty

  index = index + b3_entrypoint_sbe_size_of.last_px

  index = index + b3_entrypoint_sbe_size_of.exec_id

  index = index + b3_entrypoint_sbe_size_of.transact_time

  index = index + b3_entrypoint_sbe_size_of.leaves_qty

  index = index + b3_entrypoint_sbe_size_of.cum_qty

  index = index + b3_entrypoint_sbe_size_of.trade_id

  index = index + b3_entrypoint_sbe_size_of.contra_broker

  index = index + b3_entrypoint_sbe_size_of.order_id

  index = index + b3_entrypoint_sbe_size_of.aggressor_indicator

  index = index + b3_entrypoint_sbe_size_of.settltype_optional

  index = index + b3_entrypoint_sbe_size_of.trade_date

  index = index + b3_entrypoint_sbe_size_of.days_to_settlement_optional

  index = index + b3_entrypoint_sbe_size_of.secondary_exec_id

  index = index + b3_entrypoint_sbe_size_of.exec_ref_id

  index = index + b3_entrypoint_sbe_size_of.fixed_rate_optional

  index = index + b3_entrypoint_sbe_size_of.order_qty


  return index
end

-- Display: Execution Report Forward Message
b3_entrypoint_sbe_display.execution_report_forward_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Execution Report Forward Message
b3_entrypoint_sbe_dissect.execution_report_forward_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Outbound Business Header: 1 Byte Ascii String
  index, outbound_business_header = b3_entrypoint_sbe_dissect.outbound_business_header(buffer, index, packet, parent)

  -- Side: 1 Byte Ascii String Enum with 2 values
  index, side = b3_entrypoint_sbe_dissect.side(buffer, index, packet, parent)

  -- Ord Status: 1 Byte Ascii String Enum with 9 values
  index, ord_status = b3_entrypoint_sbe_dissect.ord_status(buffer, index, packet, parent)

  -- ClOrdId Optional: 8 Byte Unsigned Fixed Width Integer
  index, clordid_optional = b3_entrypoint_sbe_dissect.clordid_optional(buffer, index, packet, parent)

  -- Secondary Order ID: 8 Byte Unsigned Fixed Width Integer
  index, secondary_order_id = b3_entrypoint_sbe_dissect.secondary_order_id(buffer, index, packet, parent)

  -- Security ID: 8 Byte Unsigned Fixed Width Integer
  index, security_id = b3_entrypoint_sbe_dissect.security_id(buffer, index, packet, parent)

  -- Security Exchange: 4 Byte Ascii String
  index, security_exchange = b3_entrypoint_sbe_dissect.security_exchange(buffer, index, packet, parent)

  -- Account: 4 Byte Unsigned Fixed Width Integer
  index, account = b3_entrypoint_sbe_dissect.account(buffer, index, packet, parent)

  -- Last Qty: 8 Byte Unsigned Fixed Width Integer
  index, last_qty = b3_entrypoint_sbe_dissect.last_qty(buffer, index, packet, parent)

  -- Last Px: 8 Byte Signed Fixed Width Integer
  index, last_px = b3_entrypoint_sbe_dissect.last_px(buffer, index, packet, parent)

  -- Exec ID: 8 Byte Unsigned Fixed Width Integer
  index, exec_id = b3_entrypoint_sbe_dissect.exec_id(buffer, index, packet, parent)

  -- Transact Time: 8 Byte Unsigned Fixed Width Integer
  index, transact_time = b3_entrypoint_sbe_dissect.transact_time(buffer, index, packet, parent)

  -- Leaves Qty: 8 Byte Unsigned Fixed Width Integer
  index, leaves_qty = b3_entrypoint_sbe_dissect.leaves_qty(buffer, index, packet, parent)

  -- Cum Qty: 8 Byte Unsigned Fixed Width Integer
  index, cum_qty = b3_entrypoint_sbe_dissect.cum_qty(buffer, index, packet, parent)

  -- Trade ID: 4 Byte Unsigned Fixed Width Integer
  index, trade_id = b3_entrypoint_sbe_dissect.trade_id(buffer, index, packet, parent)

  -- Contra Broker: 4 Byte Unsigned Fixed Width Integer
  index, contra_broker = b3_entrypoint_sbe_dissect.contra_broker(buffer, index, packet, parent)

  -- Order ID: 8 Byte Unsigned Fixed Width Integer
  index, order_id = b3_entrypoint_sbe_dissect.order_id(buffer, index, packet, parent)

  -- Aggressor Indicator: 1 Byte Unsigned Fixed Width Integer Enum with 2 values
  index, aggressor_indicator = b3_entrypoint_sbe_dissect.aggressor_indicator(buffer, index, packet, parent)

  -- SettlType Optional: 1 Byte Ascii String Enum with 4 values
  index, settltype_optional = b3_entrypoint_sbe_dissect.settltype_optional(buffer, index, packet, parent)

  -- Trade Date: 2 Byte Unsigned Fixed Width Integer
  index, trade_date = b3_entrypoint_sbe_dissect.trade_date(buffer, index, packet, parent)

  -- Days To Settlement Optional: 2 Byte Unsigned Fixed Width Integer
  index, days_to_settlement_optional = b3_entrypoint_sbe_dissect.days_to_settlement_optional(buffer, index, packet, parent)

  -- Secondary Exec ID: 8 Byte Unsigned Fixed Width Integer
  index, secondary_exec_id = b3_entrypoint_sbe_dissect.secondary_exec_id(buffer, index, packet, parent)

  -- Exec Ref ID: 8 Byte Unsigned Fixed Width Integer
  index, exec_ref_id = b3_entrypoint_sbe_dissect.exec_ref_id(buffer, index, packet, parent)

  -- Fixed Rate Optional: 8 Byte Signed Fixed Width Integer Nullable
  index, fixed_rate_optional = b3_entrypoint_sbe_dissect.fixed_rate_optional(buffer, index, packet, parent)

  -- Order Qty: 8 Byte Unsigned Fixed Width Integer
  index, order_qty = b3_entrypoint_sbe_dissect.order_qty(buffer, index, packet, parent)


  return index
end

-- Dissect: Execution Report Forward Message
b3_entrypoint_sbe_dissect.execution_report_forward_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.execution_report_forward_message then
    local length = b3_entrypoint_sbe_size_of.execution_report_forward_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.execution_report_forward_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.execution_report_forward_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.execution_report_forward_message_fields(buffer, offset, packet, parent)
end

-- Size: Crossed Indicator
b3_entrypoint_sbe_size_of.crossed_indicator = 2

-- Display: Crossed Indicator
b3_entrypoint_sbe_display.crossed_indicator = function(value)
  if value == 1001 then
    return "Crossed indicator: STRUCTURED_TRANSACTION"
  end
  if value == 1002 then
    return "Crossed indicator: OPERATIONAL_ERROR"
  end
  if value == 1003 then
    return "Crossed indicator: TWAP_VWAP"
  end
  if value == 0 then
    return "Crossed indicator: NULL"
  end

  return "Crossed indicator: UNKNOWN("..value..")"
end

-- Dissect: Crossed Indicator
b3_entrypoint_sbe_dissect.crossed_indicator = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.crossed_indicator
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.crossed_indicator(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.crossed_indicator, range, value, display)

  return offset + length, value
end

-- Size: CrossId Optional
b3_entrypoint_sbe_size_of.crossid_optional = 8

-- Display: CrossId Optional
b3_entrypoint_sbe_display.crossid_optional = function(value)
  return "Cross ID: "..value
end

-- Dissect: CrossId Optional
b3_entrypoint_sbe_dissect.crossid_optional = function(buffer, offset, packet, parent)

  local length = b3_entrypoint_sbe_size_of.crossid_optional
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.crossid_optional(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.crossid_optional, range, value, display)

  return offset + length, value
end

-- Size: Max Floor
b3_entrypoint_sbe_size_of.max_floor = 8

-- Display: Max Floor
b3_entrypoint_sbe_display.max_floor = function(value)
  return "Max floor: "..value
end

-- Dissect: Max Floor
b3_entrypoint_sbe_dissect.max_floor = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.max_floor
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.max_floor(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.max_floor, range, value, display)

  return offset + length, value
end

-- Size: Min Qty
b3_entrypoint_sbe_size_of.min_qty = 8

-- Display: Min Qty
b3_entrypoint_sbe_display.min_qty = function(value)
  return "Min quantity: "..value
end

-- Dissect: Min Qty
b3_entrypoint_sbe_dissect.min_qty = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.min_qty
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.min_qty(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.min_qty, range, value, display)

  return offset + length, value
end

-- Size: Stop Px
b3_entrypoint_sbe_size_of.stop_px = 8

-- Display: Stop Px
b3_entrypoint_sbe_display.stop_px = function(raw, value)
  -- Check null sentinel value
  if raw == Int64(0x00000000, 0x80000000) then
    return "Stop price: NULL"
  end

  return "Stop price: "..value
end

-- Translate: Stop Px
translate.stop_px = function(raw)
  -- Check null sentinel value
  if raw == Int64(0x00000000, 0x80000000) then
    return 0/0
  end

  return raw:tonumber()/10000
end

-- Dissect: Stop Px
b3_entrypoint_sbe_dissect.stop_px = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.stop_px
  local range = buffer(offset, length)
  local raw = range:le_int64()
  local value = translate.stop_px(raw)
  local display = b3_entrypoint_sbe_display.stop_px(raw, value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.stop_px, range, value, display)

  return offset + length, value
end

-- Size: Expire Date
b3_entrypoint_sbe_size_of.expire_date = 2

-- Display: Expire Date
b3_entrypoint_sbe_display.expire_date = function(value)
  return "Expire date: "..value
end

-- Dissect: Expire Date
b3_entrypoint_sbe_dissect.expire_date = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.expire_date
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.expire_date(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.expire_date, range, value, display)

  return offset + length, value
end

-- Size: Time In Force
b3_entrypoint_sbe_size_of.time_in_force = 1

-- Display: Time In Force Simple
b3_entrypoint_sbe_display.time_in_force = function(value)
  if value == 48 then
    return "Time in force: DAY"
  end
  if value == 49 then
    return "Time in force: GOOD_TILL_CANCEL"
  end
  if value == 51 then
    return "Time in force: IMMEDIATE_OR_CANCEL"
  end
  if value == 52 then
    return "Time in force: FILL_OR_KILL"
  end
  if value == 54 then
    return "Time in force: GOOD_TILL_DATE"
  end
  if value == 55  then
    return "Time in force: AT_THE_CLOSE"
  end
  if value == 65 then
    return "Time in force: GOOD_FOR_AUCTION"
  end
  if value == 0 then
    return "Time in force: NULL"
  end

  return "Time in force: UNKNOWN("..value..")"
end

-- Dissect: Time In Force
b3_entrypoint_sbe_dissect.time_in_force = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.time_in_force
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()

  local display = b3_entrypoint_sbe_display.time_in_force(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.time_in_force, range, value, display)

  return offset + length, value
end

-- Size: OrdType
b3_entrypoint_sbe_size_of.ordtype = 1

-- Display: OrdType
b3_entrypoint_sbe_display.ordtype = function(value)
  if value == 49 then
    return "Order type: MARKET"
  end
  if value == 50 then
    return "Order type: LIMIT"
  end
  if value == 51 then
    return "Order type: STOP_LOSS"
  end
  if value == 52 then
    return "Order type: STOP_LIMIT"
  end
  if value == 75 then
    return "Order type: MARKET_WITH_LEFTOVER_AS_LIMIT"
  end
  if value == 80 then
    return "Order type: PEGGED_MIDPOINT"
  end
  if value == 87 then
    return "Order type: RLP (Retail Liquidity Provider)"
  end
  if value == 0 then
    return "Order type: NULL"
  end

  return "Order type: UNKNOWN("..value..")"
end

-- Dissect: OrdType
b3_entrypoint_sbe_dissect.ordtype = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.ordtype
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()

  local display = b3_entrypoint_sbe_display.ordtype(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.ordtype, range, value, display)

  return offset + length, value
end

-- Size: OrigClOrdId
b3_entrypoint_sbe_size_of.origclordid = 8

-- Display: OrigClOrdId
b3_entrypoint_sbe_display.origclordid = function(value)
  return "Original client order ID: "..value
end

-- Dissect: OrigClOrdId
b3_entrypoint_sbe_dissect.origclordid = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.origclordid
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.origclordid(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.origclordid, range, value, display)

  return offset + length, value
end

-- Size: Order ID Optional
b3_entrypoint_sbe_size_of.order_id_optional = 8

-- Display: Order ID Optional
b3_entrypoint_sbe_display.order_id_optional = function(value)
  return "Order ID: "..value
end

-- Dissect: Order ID Optional
b3_entrypoint_sbe_dissect.order_id_optional = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.order_id_optional
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.order_id_optional(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.order_id_optional, range, value, display)

  return offset + length, value
end

-- Size: Ord Rej Reason
b3_entrypoint_sbe_size_of.ord_rej_reason = 4

-- Display: Ord Rej Reason
b3_entrypoint_sbe_display.ord_rej_reason = function(value)
  return "Order reject reason: "..value
end

-- Dissect: Ord Rej Reason
b3_entrypoint_sbe_dissect.ord_rej_reason = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.ord_rej_reason
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.ord_rej_reason(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.ord_rej_reason, range, value, display)

  return offset + length, value
end

-- Size: Secondary Order ID Optional
b3_entrypoint_sbe_size_of.secondary_order_id_optional = 8

-- Display: Secondary Order ID Optional
b3_entrypoint_sbe_display.secondary_order_id_optional = function(value)
  return "Secondary Order ID Optional: "..value
end

-- Dissect: Secondary Order ID Optional
b3_entrypoint_sbe_dissect.secondary_order_id_optional = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.secondary_order_id_optional
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.secondary_order_id_optional(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.secondary_order_id_optional, range, value, display)

  return offset + length, value
end

-- Size: Cxl Rej Response To
b3_entrypoint_sbe_size_of.cxl_rej_response_to = 1

-- Display: Cxl Rej Response To
b3_entrypoint_sbe_display.cxl_rej_response_to = function(value)
  if value == 0 then
    return "Reject response to: NEW (SIMPLE_NEW_ORDER OR NEW_ORDER_SINGLE)"
  end
  if value == 1 then
    return "Reject response to: CANCEL (ORDER_CANCEL_REQUEST)"
  end
  if value == 2 then
    return "Reject response to: REPLACE (SIMPLE_MODIFY_ORDER OR ORDER_CANCEL_REPLACE_REQUEST)"
  end

  return "Reject response to: UNKNOWN("..value..")"
end

-- Dissect: Cxl Rej Response To
b3_entrypoint_sbe_dissect.cxl_rej_response_to = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.cxl_rej_response_to
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.cxl_rej_response_to(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.cxl_rej_response_to, range, value, display)

  return offset + length, value
end

-- Calculate size of: Execution Report Reject Message
b3_entrypoint_sbe_size_of.execution_report_reject_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.outbound_business_header

  index = index + b3_entrypoint_sbe_size_of.side

  index = index + b3_entrypoint_sbe_size_of.cxl_rej_response_to

  index = index + b3_entrypoint_sbe_size_of.clordid

  index = index + b3_entrypoint_sbe_size_of.secondary_order_id_optional

  index = index + b3_entrypoint_sbe_size_of.security_id

  index = index + b3_entrypoint_sbe_size_of.ord_rej_reason

  index = index + b3_entrypoint_sbe_size_of.transact_time

  index = index + b3_entrypoint_sbe_size_of.exec_id

  index = index + b3_entrypoint_sbe_size_of.order_id_optional

  index = index + b3_entrypoint_sbe_size_of.origclordid

  index = index + b3_entrypoint_sbe_size_of.account

  index = index + b3_entrypoint_sbe_size_of.ordtype

  index = index + b3_entrypoint_sbe_size_of.time_in_force

  index = index + b3_entrypoint_sbe_size_of.expire_date

  index = index + b3_entrypoint_sbe_size_of.order_qty

  index = index + b3_entrypoint_sbe_size_of.price_optional

  index = index + b3_entrypoint_sbe_size_of.stop_px

  index = index + b3_entrypoint_sbe_size_of.min_qty

  index = index + b3_entrypoint_sbe_size_of.max_floor

  index = index + b3_entrypoint_sbe_size_of.crossid_optional

  index = index + b3_entrypoint_sbe_size_of.crossed_indicator

  index = index + b3_entrypoint_sbe_size_of.received_time

  index = index + 3

  index = index + b3_entrypoint_sbe_size_of.ord_tag_id

  index = index + b3_entrypoint_sbe_size_of.investor_id

  index = index + b3_entrypoint_sbe_size_of.strategy_id

  index = index + b3_entrypoint_sbe_size_of.desk_id(buffer, offset + index)

  index = index + b3_entrypoint_sbe_size_of.memo(buffer, offset + index)

  index = index + b3_entrypoint_sbe_size_of.text(buffer, offset + index)

  return index
end

-- Display: Execution Report Reject Message
b3_entrypoint_sbe_display.execution_report_reject_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Execution Report Reject Message
b3_entrypoint_sbe_dissect.execution_report_reject_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Outbound Business Header: 1 Byte Ascii String
  index, outbound_business_header = b3_entrypoint_sbe_dissect.outbound_business_header(buffer, index, packet, parent)

  -- Side: 1 Byte Ascii String Enum with 2 values
  index, side = b3_entrypoint_sbe_dissect.side(buffer, index, packet, parent)

  -- Cxl Rej Response To: 1 Byte Unsigned Fixed Width Integer Enum with 3 values
  index, cxl_rej_response_to = b3_entrypoint_sbe_dissect.cxl_rej_response_to(buffer, index, packet, parent)

  -- ClOrdId: 8 Byte Unsigned Fixed Width Integer
  index, clordid = b3_entrypoint_sbe_dissect.clordid(buffer, index, packet, parent)

  -- Secondary Order ID Optional: 8 Byte Unsigned Fixed Width Integer
  index, secondary_order_id_optional = b3_entrypoint_sbe_dissect.secondary_order_id_optional(buffer, index, packet, parent)

  -- Security ID: 8 Byte Unsigned Fixed Width Integer
  index, security_id = b3_entrypoint_sbe_dissect.security_id(buffer, index, packet, parent)

  -- Ord Rej Reason: 4 Byte Unsigned Fixed Width Integer
  index, ord_rej_reason = b3_entrypoint_sbe_dissect.ord_rej_reason(buffer, index, packet, parent)

  -- Transact Time: 8 Byte Unsigned Fixed Width Integer
  index, transact_time = b3_entrypoint_sbe_dissect.transact_time(buffer, index, packet, parent)

  -- Exec ID: 8 Byte Unsigned Fixed Width Integer
  index, exec_id = b3_entrypoint_sbe_dissect.exec_id(buffer, index, packet, parent)

  -- Order ID Optional: 8 Byte Unsigned Fixed Width Integer
  index, order_id_optional = b3_entrypoint_sbe_dissect.order_id_optional(buffer, index, packet, parent)

  -- OrigClOrdId: 8 Byte Unsigned Fixed Width Integer
  index, origclordid = b3_entrypoint_sbe_dissect.origclordid(buffer, index, packet, parent)

  -- Account: 4 Byte Unsigned Fixed Width Integer
  index, account = b3_entrypoint_sbe_dissect.account(buffer, index, packet, parent)

  -- OrdType: 1 Byte Ascii String Enum with 7 values
  index, ordtype = b3_entrypoint_sbe_dissect.ordtype(buffer, index, packet, parent)

  -- Time In Force: 1 Byte Ascii String Enum with 7 values
  index, time_in_force = b3_entrypoint_sbe_dissect.time_in_force(buffer, index, packet, parent)

  -- Expire Date: 2 Byte Unsigned Fixed Width Integer
  index, expire_date = b3_entrypoint_sbe_dissect.expire_date(buffer, index, packet, parent)

  -- Order Qty: 8 Byte Unsigned Fixed Width Integer
  index, order_qty = b3_entrypoint_sbe_dissect.order_qty(buffer, index, packet, parent)

  -- Price Optional: 8 Byte Signed Fixed Width Integer Nullable
  index, price_optional = b3_entrypoint_sbe_dissect.price_optional(buffer, index, packet, parent)

  -- Stop Px: 8 Byte Signed Fixed Width Integer Nullable
  index, stop_px = b3_entrypoint_sbe_dissect.stop_px(buffer, index, packet, parent)

  -- Min Qty: 8 Byte Unsigned Fixed Width Integer
  index, min_qty = b3_entrypoint_sbe_dissect.min_qty(buffer, index, packet, parent)

  -- Max Floor: 8 Byte Unsigned Fixed Width Integer
  index, max_floor = b3_entrypoint_sbe_dissect.max_floor(buffer, index, packet, parent)

  -- CrossId Optional: 8 Byte Unsigned Fixed Width Integer
  index, crossid_optional = b3_entrypoint_sbe_dissect.crossid_optional(buffer, index, packet, parent)

  -- Crossed Indicator: 2 Byte Unsigned Fixed Width Integer Enum with 4 values
  index, crossed_indicator = b3_entrypoint_sbe_dissect.crossed_indicator(buffer, index, packet, parent)

  index, received_time = b3_entrypoint_sbe_dissect.received_time(buffer, index, packet, parent)

  index = index + 3

  index, ord_tag_id = b3_entrypoint_sbe_dissect.ord_tag_id(buffer, index, packet, parent)

  index, investor_id = b3_entrypoint_sbe_dissect.investor_id(buffer, index, packet, parent)

  index, strategy_id = b3_entrypoint_sbe_dissect.strategy_id(buffer, index, packet, parent)

  -- Desk ID: 1 Byte (Length) + N Bytes
  index, desk_id = b3_entrypoint_sbe_dissect.desk_id(buffer, index, packet, parent)

  -- Memo: 1 Byte (Length) + N Bytes
  index, memo = b3_entrypoint_sbe_dissect.memo(buffer, index, packet, parent)

  -- Text: 1 Byte (Length) + N Bytes
  index, text = b3_entrypoint_sbe_dissect.text(buffer, index, packet, parent)

  return index
end

-- Dissect: Execution Report Reject Message
b3_entrypoint_sbe_dissect.execution_report_reject_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.execution_report_reject_message then
    local length = b3_entrypoint_sbe_size_of.execution_report_reject_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.execution_report_reject_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.execution_report_reject_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.execution_report_reject_message_fields(buffer, offset, packet, parent)
end

-- Size: Tot No Related Sym
b3_entrypoint_sbe_size_of.tot_no_related_sym = 1

-- Display: Tot No Related Sym
b3_entrypoint_sbe_display.tot_no_related_sym = function(value)
  return "Tot No Related Sym: "..value
end

-- Dissect: Tot No Related Sym
b3_entrypoint_sbe_dissect.tot_no_related_sym = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.tot_no_related_sym
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.tot_no_related_sym(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.tot_no_related_sym, range, value, display)

  return offset + length, value
end

-- Size: Multi Leg Reporting Type
b3_entrypoint_sbe_size_of.multi_leg_reporting_type = 1

-- Display: Multi Leg Reporting Type
b3_entrypoint_sbe_display.multi_leg_reporting_type = function(value)
  if value == 49 then
    return "Multi leg reporting type: SINGLE_SECURITY"
  end
  if value == 50 then
    return "Multi leg reporting type: INDIVIDUALLEG_OF_MULTILEG_SECURITY"
  end
  if value == 51 then
    return "Multi leg reporting type: MULTILEG_SECURITY"
  end
  if value == 0 then
    return "Multi leg reporting type: NULL"
  end

  return "Multi Leg Reporting Type: UNKNOWN("..value..")"
end

-- Dissect: Multi Leg Reporting Type
b3_entrypoint_sbe_dissect.multi_leg_reporting_type = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.multi_leg_reporting_type
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()

  local display = b3_entrypoint_sbe_display.multi_leg_reporting_type(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.multi_leg_reporting_type, range, value, display)

  return offset + length, value
end

-- Size: Order Category
b3_entrypoint_sbe_size_of.order_category = 1

-- Display: Order Category
b3_entrypoint_sbe_display.order_category = function(value)
  if value == 66 then
    return "Order category: RESULT_OF_OPTIONS_EXERCISE"
  end
  if value == 67 then
    return "Order category: RESULT_OF_ASSIGNMENT_FROM_AN_OPTIONS_EXERCISE"
  end
  if value == 68 then
    return "Order category: RESULT_OF_AUTOMATIC_OPTIONS_EXERCISE"
  end
  if value == 69 then
    return "Order category: RESULT_OF_MIDPOINT_ORDER"
  end
  if value == 70 then
    return "Order category: RESULT_OF_BLOCK_BOOK_TRADE"
  end
  if value == 71 then
    return "Order category: RESULT_OF_TRADE_AT_CLOSE"
  end
  if value == 72 then
    return "Order category: RESULT_OF_TRADE_AT_AVERAGE"
  end
  if value == 0 then
    return "Order category: NULL"
  end

  return "Order Category: UNKNOWN("..value..")"
end

-- Dissect: Order Category
b3_entrypoint_sbe_dissect.order_category = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.order_category
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()

  local display = b3_entrypoint_sbe_display.order_category(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.order_category, range, value, display)

  return offset + length, value
end

-- Size: Exec Type
b3_entrypoint_sbe_size_of.exec_type = 1

-- Display: Exec Type
b3_entrypoint_sbe_display.exec_type = function(value)
  if value == 70 then
    return "Exec type: TRADE"
  end
  if value == 72 then
    return "Exec type: TRADE_CANCEL"
  end

  return "Exec type: UNKNOWN("..value..")"
end

-- Dissect: Exec Type
b3_entrypoint_sbe_dissect.exec_type = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.exec_type
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()

  local display = b3_entrypoint_sbe_display.exec_type(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.exec_type, range, value, display)

  return offset + length, value
end

-- Calculate size of: Execution Report Trade Message
b3_entrypoint_sbe_size_of.execution_report_trade_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.outbound_business_header

  index = index + b3_entrypoint_sbe_size_of.side

  index = index + b3_entrypoint_sbe_size_of.ord_status

  index = index + b3_entrypoint_sbe_size_of.clordid_optional

  index = index + b3_entrypoint_sbe_size_of.secondary_order_id

  index = index + b3_entrypoint_sbe_size_of.security_id

  index = index + b3_entrypoint_sbe_size_of.account

  index = index + b3_entrypoint_sbe_size_of.last_qty

  index = index + b3_entrypoint_sbe_size_of.last_px

  index = index + b3_entrypoint_sbe_size_of.exec_id

  index = index + b3_entrypoint_sbe_size_of.transact_time

  index = index + b3_entrypoint_sbe_size_of.leaves_qty

  index = index + b3_entrypoint_sbe_size_of.cum_qty

  index = index + b3_entrypoint_sbe_size_of.aggressor_indicator

  index = index + b3_entrypoint_sbe_size_of.exec_type

  index = index + b3_entrypoint_sbe_size_of.order_category

  index = index + b3_entrypoint_sbe_size_of.multi_leg_reporting_type

  index = index + b3_entrypoint_sbe_size_of.trade_id

  index = index + b3_entrypoint_sbe_size_of.contra_broker

  index = index + b3_entrypoint_sbe_size_of.order_id

  index = index + b3_entrypoint_sbe_size_of.trade_date

  index = index + b3_entrypoint_sbe_size_of.tot_no_related_sym

  -- Padding
  index = index + 1

  index = index + b3_entrypoint_sbe_size_of.secondary_exec_id

  index = index + b3_entrypoint_sbe_size_of.exec_ref_id

  index = index + b3_entrypoint_sbe_size_of.crossid_optional

  index = index + b3_entrypoint_sbe_size_of.crossed_indicator

  index = index + b3_entrypoint_sbe_size_of.order_qty

  if version >= 3 then
    index = index + b3_entrypoint_sbe_size_of.trading_session_id

    index = index + b3_entrypoint_sbe_size_of.trading_session_sub_id

    index = index + b3_entrypoint_sbe_size_of.security_trading_status

    index = index + b3_entrypoint_sbe_size_of.cross_type

    index = index + b3_entrypoint_sbe_size_of.cross_prioritization

    -- Padding
    index = index + 1

    index = index + b3_entrypoint_sbe_size_of.strategy_id
  end

  if version >= 4 then
    index = index + b3_entrypoint_sbe_size_of.implied_event_id
  end

  index = index + b3_entrypoint_sbe_size_of.desk_id(buffer, offset + index)

  index = index + b3_entrypoint_sbe_size_of.memo(buffer, offset + index)

  return index
end

-- Display: Execution Report Trade Message
b3_entrypoint_sbe_display.execution_report_trade_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Execution Report Trade Message
b3_entrypoint_sbe_dissect.execution_report_trade_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Outbound Business Header: 1 Byte Ascii String
  index, outbound_business_header = b3_entrypoint_sbe_dissect.outbound_business_header(buffer, index, packet, parent)

  -- Side: 1 Byte Ascii String Enum with 2 values
  index, side = b3_entrypoint_sbe_dissect.side(buffer, index, packet, parent)

  -- Ord Status: 1 Byte Ascii String Enum with 9 values
  index, ord_status = b3_entrypoint_sbe_dissect.ord_status(buffer, index, packet, parent)

  -- ClOrdId Optional: 8 Byte Unsigned Fixed Width Integer
  index, clordid_optional = b3_entrypoint_sbe_dissect.clordid_optional(buffer, index, packet, parent)

  -- Secondary Order ID: 8 Byte Unsigned Fixed Width Integer
  index, secondary_order_id = b3_entrypoint_sbe_dissect.secondary_order_id(buffer, index, packet, parent)

  -- Security ID: 8 Byte Unsigned Fixed Width Integer
  index, security_id = b3_entrypoint_sbe_dissect.security_id(buffer, index, packet, parent)

  -- Account: 4 Byte Unsigned Fixed Width Integer
  index, account = b3_entrypoint_sbe_dissect.account(buffer, index, packet, parent)

  -- Last Qty: 8 Byte Unsigned Fixed Width Integer
  index, last_qty = b3_entrypoint_sbe_dissect.last_qty(buffer, index, packet, parent)

  -- Last Px: 8 Byte Signed Fixed Width Integer
  index, last_px = b3_entrypoint_sbe_dissect.last_px(buffer, index, packet, parent)

  -- Exec ID: 8 Byte Unsigned Fixed Width Integer
  index, exec_id = b3_entrypoint_sbe_dissect.exec_id(buffer, index, packet, parent)

  -- Transact Time: 8 Byte Unsigned Fixed Width Integer
  index, transact_time = b3_entrypoint_sbe_dissect.transact_time(buffer, index, packet, parent)

  -- Leaves Qty: 8 Byte Unsigned Fixed Width Integer
  index, leaves_qty = b3_entrypoint_sbe_dissect.leaves_qty(buffer, index, packet, parent)

  -- Cum Qty: 8 Byte Unsigned Fixed Width Integer
  index, cum_qty = b3_entrypoint_sbe_dissect.cum_qty(buffer, index, packet, parent)

  -- Aggressor Indicator: 1 Byte Unsigned Fixed Width Integer Enum with 2 values
  index, aggressor_indicator = b3_entrypoint_sbe_dissect.aggressor_indicator(buffer, index, packet, parent)

  -- Exec Type: 1 Byte Ascii String Enum with 2 values
  index, exec_type = b3_entrypoint_sbe_dissect.exec_type(buffer, index, packet, parent)

  -- Order Category: 1 Byte Ascii String Enum with 8 values
  index, order_category = b3_entrypoint_sbe_dissect.order_category(buffer, index, packet, parent)

  -- Multi Leg Reporting Type: 1 Byte Ascii String Enum with 4 values
  index, multi_leg_reporting_type = b3_entrypoint_sbe_dissect.multi_leg_reporting_type(buffer, index, packet, parent)

  -- Trade ID: 4 Byte Unsigned Fixed Width Integer
  index, trade_id = b3_entrypoint_sbe_dissect.trade_id(buffer, index, packet, parent)

  -- Contra Broker: 4 Byte Unsigned Fixed Width Integer
  index, contra_broker = b3_entrypoint_sbe_dissect.contra_broker(buffer, index, packet, parent)

  -- Order ID: 8 Byte Unsigned Fixed Width Integer
  index, order_id = b3_entrypoint_sbe_dissect.order_id(buffer, index, packet, parent)

  -- Trade Date: 2 Byte Unsigned Fixed Width Integer
  index, trade_date = b3_entrypoint_sbe_dissect.trade_date(buffer, index, packet, parent)

  -- Tot No Related Sym: 1 Byte Unsigned Fixed Width Integer
  index, tot_no_related_sym = b3_entrypoint_sbe_dissect.tot_no_related_sym(buffer, index, packet, parent)

  -- Padding
  index = index + 1

  -- Secondary Exec ID: 8 Byte Unsigned Fixed Width Integer
  index, secondary_exec_id = b3_entrypoint_sbe_dissect.secondary_exec_id(buffer, index, packet, parent)

  -- Exec Ref ID: 8 Byte Unsigned Fixed Width Integer
  index, exec_ref_id = b3_entrypoint_sbe_dissect.exec_ref_id(buffer, index, packet, parent)

  -- CrossId Optional: 8 Byte Unsigned Fixed Width Integer
  index, crossid_optional = b3_entrypoint_sbe_dissect.crossid_optional(buffer, index, packet, parent)

  -- Crossed Indicator: 2 Byte Unsigned Fixed Width Integer Enum with 4 values
  index, crossed_indicator = b3_entrypoint_sbe_dissect.crossed_indicator(buffer, index, packet, parent)

  -- Order Qty: 8 Byte Unsigned Fixed Width Integer
  index, order_qty = b3_entrypoint_sbe_dissect.order_qty(buffer, index, packet, parent)

  if version >= 3 then
    -- Trading Session ID: 1 Byte Ascii String Enum with 3 values
    index, trading_session_id = b3_entrypoint_sbe_dissect.trading_session_id(buffer, index, packet, parent)

    -- Trading Session Sub ID: 1 Byte Ascii String Enum with 3 values
    index, trading_session_sub_id = b3_entrypoint_sbe_dissect.trading_session_sub_id(buffer, index, packet, parent)

    -- Security Trading Status: 1 Byte Ascii String Enum with 4 values
    index, security_trading_status = b3_entrypoint_sbe_dissect.security_trading_status(buffer, index, packet, parent)

    -- Cross Type: 1 Byte Ascii String Enum with 3 values
    index, cross_type = b3_entrypoint_sbe_dissect.cross_type(buffer, index, packet, parent)

    -- Cross Prioritization: 1 Byte Ascii String Enum with 3 values
    index, cross_prioritization = b3_entrypoint_sbe_dissect.cross_prioritization(buffer, index, packet, parent)

    -- Padding
    index = index + 1

    -- Strategy ID: 4 Byte Unsigned Fixed Width Integer
    index, strategy_id = b3_entrypoint_sbe_dissect.strategy_id(buffer, index, packet, parent)
  end

  if version >= 4 then
    index, implied_event_id = b3_entrypoint_sbe_dissect.implied_event_id(buffer, index, packet, parent)
  end

  -- Desk ID: 1 Byte (Length) + N Bytes
  index, desk_id = b3_entrypoint_sbe_dissect.desk_id(buffer, index, packet, parent)

  -- Memo: 1 Byte (Length) + N Bytes
  index, memo = b3_entrypoint_sbe_dissect.memo(buffer, index, packet, parent)

  return index
end

-- Dissect: Execution Report Trade Message
b3_entrypoint_sbe_dissect.execution_report_trade_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.execution_report_trade_message then
    local length = b3_entrypoint_sbe_size_of.execution_report_trade_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.execution_report_trade_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.execution_report_trade_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.execution_report_trade_message_fields(buffer, offset, packet, parent)
end

-- Size: Mass Action Report ID Optional
b3_entrypoint_sbe_size_of.mass_action_report_id_optional = 8

-- Display: Mass Action Report ID Optional
b3_entrypoint_sbe_display.mass_action_report_id_optional = function(value)
  return "Mass action report ID: "..value
end

-- Dissect: Mass Action Report ID Optional
b3_entrypoint_sbe_dissect.mass_action_report_id_optional = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.mass_action_report_id_optional
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.mass_action_report_id_optional(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.mass_action_report_id_optional, range, value, display)

  return offset + length, value
end

-- Size: Exec Restatement Reason
b3_entrypoint_sbe_size_of.exec_restatement_reason = 1

-- Display: Exec Restatement Reason
b3_entrypoint_sbe_display.exec_restatement_reason = function(value)
  if value == 8 then
    return "Exec restatement reason: MARKET_OPTION"
  end
  if value == 100 then
    return "Exec restatement reason: CANCEL_ON_HARD_DISCONNECTION"
  end
  if value == 101 then
    return "Exec restatement reason: CANCEL_ON_TERMINATE"
  end
  if value == 102 then
    return "Exec restatement reason: CANCEL_ON_DISCONNECT_AND_TERMINATE"
  end
  if value == 103 then
    return "Exec restatement reason: SELF_TRADING_PREVENTION"
  end
  if value == 105 then
    return "Exec restatement reason: CANCEL_FROM_FIRMSOFT"
  end
  if value == 107 then
    return "Exec restatement reason: CANCEL_RESTING_ORDER_ON_SELF_TRADE"
  end
  if value == 200 then
    return "Exec restatement reason: MARKET_MAKER_PROTECTION"
  end
  if value == 201 then
    return "Exec restatement reason: RISK_MANAGEMENT_CANCELLATION"
  end
  if value == 202 then
    return "Exec restatement reason: ORDER_MASS_ACTION_FROM_CLIENT_REQUEST"
  end
  if value == 203 then
    return "Exec restatement reason: CANCEL_ORDER_DUE_TO_OPERATIONAL_ERROR"
  end
  if value == 204 then
    return "Exec restatement reason: ORDER_CANCELLED_DUE_TO_OPERATIONAL_ERROR"
  end
  if value == 205 then
    return "Exec restatement reason: CANCEL_ORDER_FIRMSOFT_DUE_TO_OPERATIONAL_ERROR"
  end
  if value == 206 then
    return "Exec restatement reason: ORDER_CANCELLED_FIRMSOFT_DUE_TO_OPERATIONAL_ERROR"
  end
  if value == 207 then
    return "Exec restatement reason: MASS_CANCEL_ORDER_DUE_TO_OPERATIONAL_ERROR_REQUEST"
  end
  if value == 208 then
    return "Exec restatement reason: MASS_CANCEL_ORDER_DUE_TO_OPERATIONAL_ERROR_EFFECTIVE"
  end
  if value == 209 then
    return "Exec restatement reason: CANCEL_ON_MIDPOINT_BROKER_ONLY_REMOVAL"
  end
  if value == 210 then
    return "Exec restatement reason: CANCEL_REMAINING_FROM_SWEEP_CROSS"
  end
  if value == 211 then
    return "Exec restatement reason: MASS_CANCEL_ON_BEHALF"
  end
  if value == 212 then
    return "Exec restatement reason: MASS_CANCEL_ON_BEHALF_DUE_TO_OPERATIONAL_ERROR_EFFECTIVE"
  end
  if value == 0 then
    return "Exec restatement reason: NULL"
  end

  return "Exec Restatement Reason: UNKNOWN("..value..")"
end

-- Dissect: Exec Restatement Reason
b3_entrypoint_sbe_dissect.exec_restatement_reason = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.exec_restatement_reason
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.exec_restatement_reason(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.exec_restatement_reason, range, value, display)

  return offset + length, value
end

-- Size: Working Indicator
b3_entrypoint_sbe_size_of.working_indicator = 1

-- Display: Working Indicator
b3_entrypoint_sbe_display.working_indicator = function(value)
  if value == 0 then
    return "Working indicator: FALSE"
  end
  if value == 1 then
    return "Working indicator: TRUE"
  end

  return "Working indicator: UNKNOWN("..value..")"
end

-- Dissect: Working Indicator
b3_entrypoint_sbe_dissect.working_indicator = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.working_indicator
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.working_indicator(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.working_indicator, range, value, display)

  return offset + length, value
end

-- Size: Market Segment Received Time
b3_entrypoint_sbe_size_of.market_segment_received_time = 8

-- Display: Market Segment Received Time
b3_entrypoint_sbe_display.market_segment_received_time = function(value)
  -- Check if field has value
  if value == UInt64(0xFFFFFFFF, 0xFFFFFFFF) then
    return "Market segment received time: NULL"
  end

  return "Market segment received time: "..value
end

-- Dissect: Market Segment Received Time
b3_entrypoint_sbe_dissect.market_segment_received_time = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.market_segment_received_time
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.market_segment_received_time(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.market_segment_received_time, range, value, display)

  return offset + length, value
end

b3_entrypoint_sbe_size_of.received_time = 8
b3_entrypoint_sbe_display.received_time = function(value)
  if value == UInt64(0xFFFFFFFF, 0xFFFFFFFF) then
    return "Received time: NULL"
  end

  return "Received time: "..value
end

b3_entrypoint_sbe_dissect.received_time = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.received_time
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.received_time(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.received_time, range, value, display)

  return offset + length, value
end

-- Calculate size of: Execution Report Cancel Message
b3_entrypoint_sbe_size_of.execution_report_cancel_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.outbound_business_header

  index = index + b3_entrypoint_sbe_size_of.side

  index = index + b3_entrypoint_sbe_size_of.ord_status

  index = index + b3_entrypoint_sbe_size_of.clordid

  index = index + b3_entrypoint_sbe_size_of.secondary_order_id

  index = index + b3_entrypoint_sbe_size_of.security_id

  index = index + b3_entrypoint_sbe_size_of.cum_qty

  index = index + b3_entrypoint_sbe_size_of.account

  index = index + b3_entrypoint_sbe_size_of.exec_id

  index = index + b3_entrypoint_sbe_size_of.transact_time

  index = index + b3_entrypoint_sbe_size_of.market_segment_received_time

  index = index + b3_entrypoint_sbe_size_of.order_id

  index = index + b3_entrypoint_sbe_size_of.origclordid

  index = index + b3_entrypoint_sbe_size_of.trade_date

  index = index + b3_entrypoint_sbe_size_of.working_indicator

  index = index + b3_entrypoint_sbe_size_of.exec_restatement_reason

  -- Padding 4 Byte
  index = index + 4

  index = index + b3_entrypoint_sbe_size_of.mass_action_report_id_optional

  index = index + b3_entrypoint_sbe_size_of.ordtype

  index = index + b3_entrypoint_sbe_size_of.time_in_force

  index = index + b3_entrypoint_sbe_size_of.expire_date

  index = index + b3_entrypoint_sbe_size_of.order_qty

  index = index + b3_entrypoint_sbe_size_of.price_optional

  index = index + b3_entrypoint_sbe_size_of.stop_px

  index = index + b3_entrypoint_sbe_size_of.min_qty

  index = index + b3_entrypoint_sbe_size_of.max_floor

  if version >= 3 then
    index = index + b3_entrypoint_sbe_size_of.received_time

    -- padding 1 byte
    index = index + 3

    index = index + b3_entrypoint_sbe_size_of.ord_tag_id

    index = index + b3_entrypoint_sbe_size_of.investor_id

    index = index + b3_entrypoint_sbe_size_of.strategy_id

    index = index + b3_entrypoint_sbe_size_of.action_requested_from_session_id
  end

  index = index + b3_entrypoint_sbe_size_of.desk_id(buffer, offset + index)

  index = index + b3_entrypoint_sbe_size_of.memo(buffer, offset + index)

  return index
end

-- Display: Execution Report Cancel Message
b3_entrypoint_sbe_display.execution_report_cancel_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Execution Report Cancel Message
b3_entrypoint_sbe_dissect.execution_report_cancel_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Outbound Business Header: 1 Byte Ascii String
  index, outbound_business_header = b3_entrypoint_sbe_dissect.outbound_business_header(buffer, index, packet, parent)

  -- Side: 1 Byte Ascii String Enum with 2 values
  index, side = b3_entrypoint_sbe_dissect.side(buffer, index, packet, parent)

  -- Ord Status: 1 Byte Ascii String Enum with 9 values
  index, ord_status = b3_entrypoint_sbe_dissect.ord_status(buffer, index, packet, parent)

  -- ClOrdId: 8 Byte Unsigned Fixed Width Integer
  index, clordid = b3_entrypoint_sbe_dissect.clordid(buffer, index, packet, parent)

  -- Secondary Order ID: 8 Byte Unsigned Fixed Width Integer
  index, secondary_order_id = b3_entrypoint_sbe_dissect.secondary_order_id(buffer, index, packet, parent)

  -- Security ID: 8 Byte Unsigned Fixed Width Integer
  index, security_id = b3_entrypoint_sbe_dissect.security_id(buffer, index, packet, parent)

  -- Cum Qty: 8 Byte Unsigned Fixed Width Integer
  index, cum_qty = b3_entrypoint_sbe_dissect.cum_qty(buffer, index, packet, parent)

  -- Account: 4 Byte Unsigned Fixed Width Integer
  index, account = b3_entrypoint_sbe_dissect.account(buffer, index, packet, parent)

  -- Exec ID: 8 Byte Unsigned Fixed Width Integer
  index, exec_id = b3_entrypoint_sbe_dissect.exec_id(buffer, index, packet, parent)

  -- Transact Time: 8 Byte Unsigned Fixed Width Integer
  index, transact_time = b3_entrypoint_sbe_dissect.transact_time(buffer, index, packet, parent)

  -- Market Segment Received Time: 8 Byte Unsigned Fixed Width Integer Nullable
  index, market_segment_received_time = b3_entrypoint_sbe_dissect.market_segment_received_time(buffer, index, packet, parent)

  -- Order ID: 8 Byte Unsigned Fixed Width Integer
  index, order_id = b3_entrypoint_sbe_dissect.order_id(buffer, index, packet, parent)

  -- OrigClOrdId: 8 Byte Unsigned Fixed Width Integer
  index, origclordid = b3_entrypoint_sbe_dissect.origclordid(buffer, index, packet, parent)

  -- Trade Date: 2 Byte Unsigned Fixed Width Integer
  index, trade_date = b3_entrypoint_sbe_dissect.trade_date(buffer, index, packet, parent)

  -- Working Indicator: 1 Byte Unsigned Fixed Width Integer Enum with 2 values
  index, working_indicator = b3_entrypoint_sbe_dissect.working_indicator(buffer, index, packet, parent)

  -- Exec Restatement Reason: 1 Byte Unsigned Fixed Width Integer Enum with 18 values
  index, exec_restatement_reason = b3_entrypoint_sbe_dissect.exec_restatement_reason(buffer, index, packet, parent)

  -- Padding
  index = index + 4

  -- Mass Action Report ID Optional: 8 Byte Unsigned Fixed Width Integer
  index, mass_action_report_id_optional = b3_entrypoint_sbe_dissect.mass_action_report_id_optional(buffer, index, packet, parent)

  -- OrdType: 1 Byte Ascii String Enum with 7 values
  index, ordtype = b3_entrypoint_sbe_dissect.ordtype(buffer, index, packet, parent)

  -- Time In Force: 1 Byte Ascii String Enum with 7 values
  index, time_in_force = b3_entrypoint_sbe_dissect.time_in_force(buffer, index, packet, parent)

  -- Expire Date: 2 Byte Unsigned Fixed Width Integer
  index, expire_date = b3_entrypoint_sbe_dissect.expire_date(buffer, index, packet, parent)

  -- Order Qty: 8 Byte Unsigned Fixed Width Integer
  index, order_qty = b3_entrypoint_sbe_dissect.order_qty(buffer, index, packet, parent)

  -- Price Optional: 8 Byte Signed Fixed Width Integer Nullable
  index, price_optional = b3_entrypoint_sbe_dissect.price_optional(buffer, index, packet, parent)

  -- Stop Px: 8 Byte Signed Fixed Width Integer Nullable
  index, stop_px = b3_entrypoint_sbe_dissect.stop_px(buffer, index, packet, parent)

  -- Min Qty: 8 Byte Unsigned Fixed Width Integer
  index, min_qty = b3_entrypoint_sbe_dissect.min_qty(buffer, index, packet, parent)

  -- Max Floor: 8 Byte Unsigned Fixed Width Integer
  index, max_floor = b3_entrypoint_sbe_dissect.max_floor(buffer, index, packet, parent)

  if version >= 3 then
    index, received_time = b3_entrypoint_sbe_dissect.received_time(buffer, index, packet, parent)

    -- padding 1 byte
    index = index + 3

    index, ord_tag_id = b3_entrypoint_sbe_dissect.ord_tag_id(buffer, index, packet, parent)

    index, investor_id = b3_entrypoint_sbe_dissect.investor_id(buffer, index, packet, parent)

    index, strategy_id = b3_entrypoint_sbe_dissect.strategy_id(buffer, index, packet, parent)

    index, action_request_from_session_id = b3_entrypoint_sbe_dissect.action_requested_from_session_id(buffer, index, packet, parent)
  end

  -- Desk ID: 1 Byte (Length) + N Bytes
  index, desk_id = b3_entrypoint_sbe_dissect.desk_id(buffer, index, packet, parent)

  -- Memo: 1 Byte (Length) + N Bytes
  index, memo = b3_entrypoint_sbe_dissect.memo(buffer, index, packet, parent)

  return index
end

-- Dissect: Execution Report Cancel Message
b3_entrypoint_sbe_dissect.execution_report_cancel_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.execution_report_cancel_message then
    local length = b3_entrypoint_sbe_size_of.execution_report_cancel_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.execution_report_cancel_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.execution_report_cancel_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.execution_report_cancel_message_fields(buffer, offset, packet, parent)
end

-- Size: Protection Price
b3_entrypoint_sbe_size_of.protection_price = 8

-- Display: Protection Price
b3_entrypoint_sbe_display.protection_price = function(raw, value)
  -- Check null sentinel value
  if raw == Int64(0x00000000, 0x80000000) then
    return "Protection price: NULL"
  end

  return "Protection price: "..value
end

-- Translate: Protection Price
translate.protection_price = function(raw)
  -- Check null sentinel value
  if raw == Int64(0x00000000, 0x80000000) then
    return 0/0
  end

  return raw:tonumber()/10000
end

-- Dissect: Protection Price
b3_entrypoint_sbe_dissect.protection_price = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.protection_price
  local range = buffer(offset, length)
  local raw = range:le_int64()
  local value = translate.protection_price(raw)
  local display = b3_entrypoint_sbe_display.protection_price(raw, value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.protection_price, range, value, display)

  return offset + length, value
end

-- Calculate size of: Execution Report Modify Message
b3_entrypoint_sbe_size_of.execution_report_modify_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.outbound_business_header

  index = index + b3_entrypoint_sbe_size_of.side

  index = index + b3_entrypoint_sbe_size_of.ord_status

  index = index + b3_entrypoint_sbe_size_of.clordid

  index = index + b3_entrypoint_sbe_size_of.secondary_order_id

  index = index + b3_entrypoint_sbe_size_of.security_id

  index = index + b3_entrypoint_sbe_size_of.leaves_qty

  index = index + b3_entrypoint_sbe_size_of.account

  index = index + b3_entrypoint_sbe_size_of.exec_id

  index = index + b3_entrypoint_sbe_size_of.transact_time

  index = index + b3_entrypoint_sbe_size_of.cum_qty

  index = index + b3_entrypoint_sbe_size_of.market_segment_received_time

  index = index + b3_entrypoint_sbe_size_of.order_id

  index = index + b3_entrypoint_sbe_size_of.origclordid

  index = index + b3_entrypoint_sbe_size_of.protection_price

  index = index + b3_entrypoint_sbe_size_of.trade_date

  index = index + b3_entrypoint_sbe_size_of.working_indicator

  index = index + b3_entrypoint_sbe_size_of.multi_leg_reporting_type

  index = index + b3_entrypoint_sbe_size_of.ordtype

  index = index + b3_entrypoint_sbe_size_of.time_in_force

  index = index + b3_entrypoint_sbe_size_of.expire_date

  index = index + b3_entrypoint_sbe_size_of.order_qty

  index = index + b3_entrypoint_sbe_size_of.price_optional

  index = index + b3_entrypoint_sbe_size_of.stop_px

  index = index + b3_entrypoint_sbe_size_of.min_qty

  index = index + b3_entrypoint_sbe_size_of.max_floor

  if version >= 3 then
    index = index + b3_entrypoint_sbe_size_of.received_time

    -- padding 1 byte
    index = index + 3

    index = index + b3_entrypoint_sbe_size_of.ord_tag_id

    index = index + b3_entrypoint_sbe_size_of.investor_id

    index = index + b3_entrypoint_sbe_size_of.mm_protection_reset

    -- padding 1 byte
    index = index + 1

    index = index + b3_entrypoint_sbe_size_of.strategy_id
  end

  index = index + b3_entrypoint_sbe_size_of.desk_id(buffer, offset + index)

  index = index + b3_entrypoint_sbe_size_of.memo(buffer, offset + index)

  return index
end

-- Display: Execution Report Modify Message
b3_entrypoint_sbe_display.execution_report_modify_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Execution Report Modify Message
b3_entrypoint_sbe_dissect.execution_report_modify_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Outbound Business Header: 1 Byte Ascii String
  index, outbound_business_header = b3_entrypoint_sbe_dissect.outbound_business_header(buffer, index, packet, parent)

  -- Side: 1 Byte Ascii String Enum with 2 values
  index, side = b3_entrypoint_sbe_dissect.side(buffer, index, packet, parent)

  -- Ord Status: 1 Byte Ascii String Enum with 9 values
  index, ord_status = b3_entrypoint_sbe_dissect.ord_status(buffer, index, packet, parent)

  -- ClOrdId: 8 Byte Unsigned Fixed Width Integer
  index, clordid = b3_entrypoint_sbe_dissect.clordid(buffer, index, packet, parent)

  -- Secondary Order ID: 8 Byte Unsigned Fixed Width Integer
  index, secondary_order_id = b3_entrypoint_sbe_dissect.secondary_order_id(buffer, index, packet, parent)

  -- Security ID: 8 Byte Unsigned Fixed Width Integer
  index, security_id = b3_entrypoint_sbe_dissect.security_id(buffer, index, packet, parent)

  -- Leaves Qty: 8 Byte Unsigned Fixed Width Integer
  index, leaves_qty = b3_entrypoint_sbe_dissect.leaves_qty(buffer, index, packet, parent)

  -- Account: 4 Byte Unsigned Fixed Width Integer
  index, account = b3_entrypoint_sbe_dissect.account(buffer, index, packet, parent)

  -- Exec ID: 8 Byte Unsigned Fixed Width Integer
  index, exec_id = b3_entrypoint_sbe_dissect.exec_id(buffer, index, packet, parent)

  -- Transact Time: 8 Byte Unsigned Fixed Width Integer
  index, transact_time = b3_entrypoint_sbe_dissect.transact_time(buffer, index, packet, parent)

  -- Cum Qty: 8 Byte Unsigned Fixed Width Integer
  index, cum_qty = b3_entrypoint_sbe_dissect.cum_qty(buffer, index, packet, parent)

  -- Market Segment Received Time: 8 Byte Unsigned Fixed Width Integer Nullable
  index, market_segment_received_time = b3_entrypoint_sbe_dissect.market_segment_received_time(buffer, index, packet, parent)

  -- Order ID: 8 Byte Unsigned Fixed Width Integer
  index, order_id = b3_entrypoint_sbe_dissect.order_id(buffer, index, packet, parent)

  -- OrigClOrdId: 8 Byte Unsigned Fixed Width Integer
  index, origclordid = b3_entrypoint_sbe_dissect.origclordid(buffer, index, packet, parent)

  -- Protection Price: 8 Byte Signed Fixed Width Integer Nullable
  index, protection_price = b3_entrypoint_sbe_dissect.protection_price(buffer, index, packet, parent)

  -- Trade Date: 2 Byte Unsigned Fixed Width Integer
  index, trade_date = b3_entrypoint_sbe_dissect.trade_date(buffer, index, packet, parent)

  -- Working Indicator: 1 Byte Unsigned Fixed Width Integer Enum with 2 values
  index, working_indicator = b3_entrypoint_sbe_dissect.working_indicator(buffer, index, packet, parent)

  -- Multi Leg Reporting Type: 1 Byte Ascii String Enum with 4 values
  index, multi_leg_reporting_type = b3_entrypoint_sbe_dissect.multi_leg_reporting_type(buffer, index, packet, parent)

  -- OrdType: 1 Byte Ascii String Enum with 7 values
  index, ordtype = b3_entrypoint_sbe_dissect.ordtype(buffer, index, packet, parent)

  -- Time In Force: 1 Byte Ascii String Enum with 7 values
  index, time_in_force = b3_entrypoint_sbe_dissect.time_in_force(buffer, index, packet, parent)

  -- Expire Date: 2 Byte Unsigned Fixed Width Integer
  index, expire_date = b3_entrypoint_sbe_dissect.expire_date(buffer, index, packet, parent)

  -- Order Qty: 8 Byte Unsigned Fixed Width Integer
  index, order_qty = b3_entrypoint_sbe_dissect.order_qty(buffer, index, packet, parent)

  -- Price Optional: 8 Byte Signed Fixed Width Integer Nullable
  index, price_optional = b3_entrypoint_sbe_dissect.price_optional(buffer, index, packet, parent)

  -- Stop Px: 8 Byte Signed Fixed Width Integer Nullable
  index, stop_px = b3_entrypoint_sbe_dissect.stop_px(buffer, index, packet, parent)

  -- Min Qty: 8 Byte Unsigned Fixed Width Integer
  index, min_qty = b3_entrypoint_sbe_dissect.min_qty(buffer, index, packet, parent)

  -- Max Floor: 8 Byte Unsigned Fixed Width Integer
  index, max_floor = b3_entrypoint_sbe_dissect.max_floor(buffer, index, packet, parent)

  if version >= 3 then
    index, received_time = b3_entrypoint_sbe_dissect.received_time(buffer, index, packet, parent)

    -- padding 1 byte
    index = index + 3

    index, ord_tag_id = b3_entrypoint_sbe_dissect.ord_tag_id(buffer, index, packet, parent)

    index, investor_id = b3_entrypoint_sbe_dissect.investor_id(buffer, index, packet, parent)

    index, mm_protection_reset = b3_entrypoint_sbe_dissect.mm_protection_reset(buffer, index, packet, parent)

    -- padding 1 byte
    index = index + 1

    index, strategy_id = b3_entrypoint_sbe_dissect.strategy_id(buffer, index, packet, parent)
  end

  -- Desk ID: 1 Byte (Length) + N Bytes
  index, desk_id = b3_entrypoint_sbe_dissect.desk_id(buffer, index, packet, parent)

  -- Memo: 1 Byte (Length) + N Bytes
  index, memo = b3_entrypoint_sbe_dissect.memo(buffer, index, packet, parent)

  return index
end

-- Dissect: Execution Report Modify Message
b3_entrypoint_sbe_dissect.execution_report_modify_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.execution_report_modify_message then
    local length = b3_entrypoint_sbe_size_of.execution_report_modify_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.execution_report_modify_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.execution_report_modify_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.execution_report_modify_message_fields(buffer, offset, packet, parent)
end

-- Calculate size of: Execution Report New Message
b3_entrypoint_sbe_size_of.execution_report_new_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.outbound_business_header

  index = index + b3_entrypoint_sbe_size_of.side

  index = index + b3_entrypoint_sbe_size_of.ord_status

  index = index + b3_entrypoint_sbe_size_of.clordid

  index = index + b3_entrypoint_sbe_size_of.secondary_order_id

  index = index + b3_entrypoint_sbe_size_of.security_id

  index = index + b3_entrypoint_sbe_size_of.order_id

  index = index + b3_entrypoint_sbe_size_of.account

  index = index + b3_entrypoint_sbe_size_of.exec_id

  index = index + b3_entrypoint_sbe_size_of.transact_time

  index = index + b3_entrypoint_sbe_size_of.market_segment_received_time

  index = index + b3_entrypoint_sbe_size_of.protection_price

  index = index + b3_entrypoint_sbe_size_of.trade_date

  index = index + b3_entrypoint_sbe_size_of.working_indicator

  index = index + b3_entrypoint_sbe_size_of.multi_leg_reporting_type

  index = index + b3_entrypoint_sbe_size_of.ordtype

  index = index + b3_entrypoint_sbe_size_of.time_in_force

  index = index + b3_entrypoint_sbe_size_of.expire_date

  index = index + b3_entrypoint_sbe_size_of.order_qty

  index = index + b3_entrypoint_sbe_size_of.price_optional

  index = index + b3_entrypoint_sbe_size_of.stop_px

  index = index + b3_entrypoint_sbe_size_of.min_qty

  index = index + b3_entrypoint_sbe_size_of.max_floor

  index = index + b3_entrypoint_sbe_size_of.crossid_optional

  if version >= 3 then
    index = index + b3_entrypoint_sbe_size_of.received_time

    -- padding 1 byte
    index = index + 3

    index = index + b3_entrypoint_sbe_size_of.ord_tag_id

    index = index + b3_entrypoint_sbe_size_of.investor_id

    index = index + b3_entrypoint_sbe_size_of.cross_type

    index = index + b3_entrypoint_sbe_size_of.cross_prioritization

    index = index + b3_entrypoint_sbe_size_of.mm_protection_reset

    -- padding 1 byte
    index = index + 1

    index = index + b3_entrypoint_sbe_size_of.strategy_id
  end

  index = index + b3_entrypoint_sbe_size_of.desk_id(buffer, offset + index)

  index = index + b3_entrypoint_sbe_size_of.memo(buffer, offset + index)

  return index
end

-- Display: Execution Report New Message
b3_entrypoint_sbe_display.execution_report_new_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Execution Report New Message
b3_entrypoint_sbe_dissect.execution_report_new_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Outbound Business Header: 1 Byte Ascii String
  index, outbound_business_header = b3_entrypoint_sbe_dissect.outbound_business_header(buffer, index, packet, parent)

  -- Side: 1 Byte Ascii String Enum with 2 values
  index, side = b3_entrypoint_sbe_dissect.side(buffer, index, packet, parent)

  -- Ord Status: 1 Byte Ascii String Enum with 9 values
  index, ord_status = b3_entrypoint_sbe_dissect.ord_status(buffer, index, packet, parent)

  -- ClOrdId: 8 Byte Unsigned Fixed Width Integer
  index, clordid = b3_entrypoint_sbe_dissect.clordid(buffer, index, packet, parent)

  -- Secondary Order ID: 8 Byte Unsigned Fixed Width Integer
  index, secondary_order_id = b3_entrypoint_sbe_dissect.secondary_order_id(buffer, index, packet, parent)

  -- Security ID: 8 Byte Unsigned Fixed Width Integer
  index, security_id = b3_entrypoint_sbe_dissect.security_id(buffer, index, packet, parent)

  -- Order ID: 8 Byte Unsigned Fixed Width Integer
  index, order_id = b3_entrypoint_sbe_dissect.order_id(buffer, index, packet, parent)

  -- Account: 4 Byte Unsigned Fixed Width Integer
  index, account = b3_entrypoint_sbe_dissect.account(buffer, index, packet, parent)

  -- Exec ID: 8 Byte Unsigned Fixed Width Integer
  index, exec_id = b3_entrypoint_sbe_dissect.exec_id(buffer, index, packet, parent)

  -- Transact Time: 8 Byte Unsigned Fixed Width Integer
  index, transact_time = b3_entrypoint_sbe_dissect.transact_time(buffer, index, packet, parent)

  -- Market Segment Received Time: 8 Byte Unsigned Fixed Width Integer Nullable
  index, market_segment_received_time = b3_entrypoint_sbe_dissect.market_segment_received_time(buffer, index, packet, parent)

  -- Protection Price: 8 Byte Signed Fixed Width Integer Nullable
  index, protection_price = b3_entrypoint_sbe_dissect.protection_price(buffer, index, packet, parent)

  -- Trade Date: 2 Byte Unsigned Fixed Width Integer
  index, trade_date = b3_entrypoint_sbe_dissect.trade_date(buffer, index, packet, parent)

  -- Working Indicator: 1 Byte Unsigned Fixed Width Integer Enum with 2 values
  index, working_indicator = b3_entrypoint_sbe_dissect.working_indicator(buffer, index, packet, parent)

  -- Multi Leg Reporting Type: 1 Byte Ascii String Enum with 4 values
  index, multi_leg_reporting_type = b3_entrypoint_sbe_dissect.multi_leg_reporting_type(buffer, index, packet, parent)

  -- OrdType: 1 Byte Ascii String Enum with 7 values
  index, ordtype = b3_entrypoint_sbe_dissect.ordtype(buffer, index, packet, parent)

  -- Time In Force: 1 Byte Ascii String Enum with 7 values
  index, time_in_force = b3_entrypoint_sbe_dissect.time_in_force(buffer, index, packet, parent)

  -- Expire Date: 2 Byte Unsigned Fixed Width Integer
  index, expire_date = b3_entrypoint_sbe_dissect.expire_date(buffer, index, packet, parent)

  -- Order Qty: 8 Byte Unsigned Fixed Width Integer
  index, order_qty = b3_entrypoint_sbe_dissect.order_qty(buffer, index, packet, parent)

  -- Price Optional: 8 Byte Signed Fixed Width Integer Nullable
  index, price_optional = b3_entrypoint_sbe_dissect.price_optional(buffer, index, packet, parent)

  -- Stop Px: 8 Byte Signed Fixed Width Integer Nullable
  index, stop_px = b3_entrypoint_sbe_dissect.stop_px(buffer, index, packet, parent)

  -- Min Qty: 8 Byte Unsigned Fixed Width Integer
  index, min_qty = b3_entrypoint_sbe_dissect.min_qty(buffer, index, packet, parent)

  -- Max Floor: 8 Byte Unsigned Fixed Width Integer
  index, max_floor = b3_entrypoint_sbe_dissect.max_floor(buffer, index, packet, parent)

  -- CrossId Optional: 8 Byte Unsigned Fixed Width Integer
  index, crossid_optional = b3_entrypoint_sbe_dissect.crossid_optional(buffer, index, packet, parent)

  if version >= 3 then
    index, received_time = b3_entrypoint_sbe_dissect.received_time(buffer, index, packet, parent)

    -- padding 1 byte
    index = index + 3

    index, ord_tag_id = b3_entrypoint_sbe_dissect.ord_tag_id(buffer, index, packet, parent)

    index, investor_id = b3_entrypoint_sbe_dissect.investor_id(buffer, index, packet, parent)

    index, cross_type = b3_entrypoint_sbe_dissect.cross_type(buffer, index, packet, parent)

    index, cross_prioritization = b3_entrypoint_sbe_dissect.cross_prioritization(buffer, index, packet, parent)

    index, mm_protection_reset = b3_entrypoint_sbe_dissect.mm_protection_reset(buffer, index, packet, parent)

    -- padding 1 byte
    index = index + 1

    index, strategy_id = b3_entrypoint_sbe_dissect.strategy_id(buffer, index, packet, parent)
  end

  -- Desk ID: 1 Byte (Length) + N Bytes
  index, desk_id = b3_entrypoint_sbe_dissect.desk_id(buffer, index, packet, parent)

  -- Memo: 1 Byte (Length) + N Bytes
  index, memo = b3_entrypoint_sbe_dissect.memo(buffer, index, packet, parent)


  return index
end

-- Dissect: Execution Report New Message
b3_entrypoint_sbe_dissect.execution_report_new_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.execution_report_new_message then
    local length = b3_entrypoint_sbe_size_of.execution_report_new_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.execution_report_new_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.execution_report_new_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.execution_report_new_message_fields(buffer, offset, packet, parent)
end

-- Size: Executing Trader Optional
b3_entrypoint_sbe_size_of.executing_trader_optional = 5

-- Display: Executing Trader Optional
b3_entrypoint_sbe_display.executing_trader_optional = function(value)
  -- Check if field has value
  if value == nil or value == '' then
    return "Executing trader: NULL"
  end

  return "Executing trader: "..value
end

-- Dissect: Executing Trader Optional
b3_entrypoint_sbe_dissect.executing_trader_optional = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.executing_trader_optional
  local range = buffer(offset, length)

  -- parse last octet
  local last = buffer(offset + length - 1, 1):uint()

  -- read full string or up to first zero
  local value = ''
  if last == 0 then
    value = range:stringz()
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.executing_trader_optional(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.executing_trader_optional, range, value, display)

  return offset + length, value
end

-- Size: CrossId
b3_entrypoint_sbe_size_of.crossid = 8

-- Display: CrossId
b3_entrypoint_sbe_display.crossid = function(value)
  return "Cross ID: "..value
end

-- Dissect: CrossId
b3_entrypoint_sbe_dissect.crossid = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.crossid
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.crossid(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.crossid, range, value, display)

  return offset + length, value
end

-- Calculate size of: New Order Cross Message
b3_entrypoint_sbe_size_of.new_order_cross_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.inbound_business_header

  -- Padding 2 Byte
  index = index + 2

  index = index + b3_entrypoint_sbe_size_of.crossid

  index = index + b3_entrypoint_sbe_size_of.sender_location

  index = index + b3_entrypoint_sbe_size_of.entering_trader

  index = index + b3_entrypoint_sbe_size_of.executing_trader_optional

  index = index + b3_entrypoint_sbe_size_of.security_id

  index = index + b3_entrypoint_sbe_size_of.order_qty

  index = index + b3_entrypoint_sbe_size_of.price

  index = index + b3_entrypoint_sbe_size_of.crossed_indicator

  index = index + b3_entrypoint_sbe_size_of.cross_type

  index = index + b3_entrypoint_sbe_size_of.cross_prioritization

  index = index + b3_entrypoint_sbe_size_of.max_sweep_qty

  index = index + b3_entrypoint_sbe_size_of.no_sides_groups(buffer, offset + index)

  index = index + b3_entrypoint_sbe_size_of.desk_id(buffer, offset + index)

  index = index + b3_entrypoint_sbe_size_of.memo(buffer, offset + index)

  return index
end

-- Display: New Order Cross Message
b3_entrypoint_sbe_display.new_order_cross_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: New Order Cross Message
b3_entrypoint_sbe_dissect.new_order_cross_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Inbound Business Header: 1 Byte Ascii String
  index, inbound_business_header = b3_entrypoint_sbe_dissect.inbound_business_header(buffer, index, packet, parent)

  -- Padding 2 Byte
  index = index + 2

  -- CrossId: 8 Byte Unsigned Fixed Width Integer
  index, crossid = b3_entrypoint_sbe_dissect.crossid(buffer, index, packet, parent)

  -- Sender Location: 10 Byte Ascii String
  index, sender_location = b3_entrypoint_sbe_dissect.sender_location(buffer, index, packet, parent)

  -- Entering Trader: 5 Byte Ascii String
  index, entering_trader = b3_entrypoint_sbe_dissect.entering_trader(buffer, index, packet, parent)

  -- Executing Trader Optional: 5 Byte Ascii String
  index, executing_trader_optional = b3_entrypoint_sbe_dissect.executing_trader_optional(buffer, index, packet, parent)

  -- Security ID: 8 Byte Unsigned Fixed Width Integer
  index, security_id = b3_entrypoint_sbe_dissect.security_id(buffer, index, packet, parent)

  -- Order Qty: 8 Byte Unsigned Fixed Width Integer
  index, order_qty = b3_entrypoint_sbe_dissect.order_qty(buffer, index, packet, parent)

  -- Price: 8 Byte Signed Fixed Width Integer
  index, price = b3_entrypoint_sbe_dissect.price(buffer, index, packet, parent)

  -- Crossed Indicator: 2 Byte Unsigned Fixed Width Integer Enum with 4 values
  index, crossed_indicator = b3_entrypoint_sbe_dissect.crossed_indicator(buffer, index, packet, parent)

  -- Cross Type: 1 Byte Ascii String Enum with 3 values
  index, cross_type = b3_entrypoint_sbe_dissect.cross_type(buffer, index, packet, parent)

  -- Cross Prioritization: 1 Byte Ascii String Enum with 3 values
  index, cross_prioritization = b3_entrypoint_sbe_dissect.cross_prioritization(buffer, index, packet, parent)

  -- Max Sweep Qty: 8 Byte Unsigned Fixed Width Integer
  index, max_sweep_qty = b3_entrypoint_sbe_dissect.max_sweep_qty(buffer, index, packet, parent)

  -- No Sides Groups: Struct of 2 fields
  index, no_sides_groups = b3_entrypoint_sbe_dissect.no_sides_groups(buffer, index, packet, parent)

  -- Desk ID: 1 Byte (Length) + N Bytes
  index, desk_id = b3_entrypoint_sbe_dissect.desk_id(buffer, index, packet, parent)

  -- Memo: 1 Byte (Length) + N Bytes
  index, memo = b3_entrypoint_sbe_dissect.memo(buffer, index, packet, parent)

  return index
end

-- Dissect: New Order Cross Message
b3_entrypoint_sbe_dissect.new_order_cross_message = function(buffer, offset, packet, parent)
  -- Optionally add dynamic struct element to protocol tree
  if show.new_order_cross_message then
    local length = b3_entrypoint_sbe_size_of.new_order_cross_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.new_order_cross_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.new_order_cross_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.new_order_cross_message_fields(buffer, offset, packet, parent)
end

-- Size: Single Cancel Restatement Reason
b3_entrypoint_sbe_size_of.single_cancel_restatement_reason = 1

-- Display: Single Cancel Restatement Reason
b3_entrypoint_sbe_display.single_cancel_restatement_reason = function(value)
  if value == 8 then
    return "Exec restatement reason: MARKET_OPTION (NOT VALID FOR ORDER CANCEL REQUEST)"
  end
  if value == 100 then
    return "Exec restatement reason: CANCEL_ON_HARD_DISCONNECTION (NOT VALID FOR ORDER CANCEL REQUEST)"
  end
  if value == 101 then
    return "Exec restatement reason: CANCEL_ON_TERMINATE (NOT VALID FOR ORDER CANCEL REQUEST)"
  end
  if value == 102 then
    return "Exec restatement reason: CANCEL_ON_DISCONNECT_AND_TERMINATE (NOT VALID FOR ORDER CANCEL REQUEST)"
  end
  if value == 103 then
    return "Exec restatement reason: SELF_TRADING_PREVENTION (NOT VALID FOR ORDER CANCEL REQUEST)"
  end
  if value == 105 then
    return "Exec restatement reason: CANCEL_FROM_FIRMSOFT (NOT VALID FOR ORDER CANCEL REQUEST)"
  end
  if value == 107 then
    return "Exec restatement reason: CANCEL_RESTING_ORDER_ON_SELF_TRADE (NOT VALID FOR ORDER CANCEL REQUEST)"
  end
  if value == 200 then
    return "Exec restatement reason: MARKET_MAKER_PROTECTION (NOT VALID FOR ORDER CANCEL REQUEST)"
  end
  if value == 201 then
    return "Exec restatement reason: RISK_MANAGEMENT_CANCELLATION (NOT VALID FOR ORDER CANCEL REQUEST)"
  end
  if value == 202 then
    return "Exec restatement reason: ORDER_MASS_ACTION_FROM_CLIENT_REQUEST (NOT VALID FOR ORDER CANCEL REQUEST)"
  end
  if value == 203 then
    return "Exec restatement reason: CANCEL_ORDER_DUE_TO_OPERATIONAL_ERROR"
  end
  if value == 204 then
    return "Exec restatement reason: ORDER_CANCELLED_DUE_TO_OPERATIONAL_ERROR (NOT VALID FOR ORDER CANCEL REQUEST)"
  end
  if value == 205 then
    return "Exec restatement reason: CANCEL_ORDER_FIRMSOFT_DUE_TO_OPERATIONAL_ERROR (NOT VALID FOR ORDER CANCEL REQUEST)"
  end
  if value == 206 then
    return "Exec restatement reason: ORDER_CANCELLED_FIRMSOFT_DUE_TO_OPERATIONAL_ERROR (NOT VALID FOR ORDER CANCEL REQUEST)"
  end
  if value == 207 then
    return "Exec restatement reason: MASS_CANCEL_ORDER_DUE_TO_OPERATIONAL_ERROR_REQUEST (NOT VALID FOR ORDER CANCEL REQUEST)"
  end
  if value == 208 then
    return "Exec restatement reason: MASS_CANCEL_ORDER_DUE_TO_OPERATIONAL_ERROR_EFFECTIVE (NOT VALID FOR ORDER CANCEL REQUEST)"
  end
  if value == 209 then
    return "Exec restatement reason: CANCEL_ON_MIDPOINT_BROKER_ONLY_REMOVAL (NOT VALID FOR ORDER CANCEL REQUEST)"
  end
  if value == 210 then
    return "Exec restatement reason: CANCEL_REMAINING_FROM_SWEEP_CROSS (NOT VALID FOR ORDER CANCEL REQUEST)"
  end
  if value == 211 then
    return "Exec restatement reason: MASS_CANCEL_ON_BEHALF (NOT VALID FOR ORDER CANCEL REQUEST)"
  end
  if value == 212 then
    return "Exec restatement reason: MASS_CANCEL_ON_BEHALF_DUE_TO_OPERATIONAL_ERROR_EFFECTIVE (NOT VALID FOR ORDER CANCEL REQUEST)"
  end
  if value == 0 then
    return "Exec restatement reason: NULL"
  end

  return "Exec Restatement Reason: UNKNOWN("..value..")"
end

-- Dissect: Single Cancel Restatement Reason
b3_entrypoint_sbe_dissect.single_cancel_restatement_reason = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.single_cancel_restatement_reason
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.single_cancel_restatement_reason(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.single_cancel_restatement_reason, range, value, display)

  return offset + length, value
end

-- Calculate size of: Order Cancel Request Message
b3_entrypoint_sbe_size_of.order_cancel_request_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.inbound_business_header

  -- Padding
  index = index + 2

  index = index + b3_entrypoint_sbe_size_of.clordid

  index = index + b3_entrypoint_sbe_size_of.security_id

  index = index + b3_entrypoint_sbe_size_of.order_id_optional

  index = index + b3_entrypoint_sbe_size_of.origclordid

  index = index + b3_entrypoint_sbe_size_of.side

  index = index + b3_entrypoint_sbe_size_of.single_cancel_restatement_reason

  -- Padding
  index = index + 2

  index = index + b3_entrypoint_sbe_size_of.sender_location

  index = index + b3_entrypoint_sbe_size_of.entering_trader

  index = index + b3_entrypoint_sbe_size_of.executing_trader_optional

  index = index + b3_entrypoint_sbe_size_of.desk_id(buffer, offset + index)

  index = index + b3_entrypoint_sbe_size_of.memo(buffer, offset + index)

  return index
end

-- Display: Order Cancel Request Message
b3_entrypoint_sbe_display.order_cancel_request_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Order Cancel Request Message
b3_entrypoint_sbe_dissect.order_cancel_request_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Inbound Business Header: 1 Byte Ascii String
  index, inbound_business_header = b3_entrypoint_sbe_dissect.inbound_business_header(buffer, index, packet, parent)

  -- Padding
  index = index + 2

  -- ClOrdId: 8 Byte Unsigned Fixed Width Integer
  index, clordid = b3_entrypoint_sbe_dissect.clordid(buffer, index, packet, parent)

  -- Security ID: 8 Byte Unsigned Fixed Width Integer
  index, security_id = b3_entrypoint_sbe_dissect.security_id(buffer, index, packet, parent)

  -- Order ID Optional: 8 Byte Unsigned Fixed Width Integer
  index, order_id_optional = b3_entrypoint_sbe_dissect.order_id_optional(buffer, index, packet, parent)

  -- OrigClOrdId: 8 Byte Unsigned Fixed Width Integer
  index, origclordid = b3_entrypoint_sbe_dissect.origclordid(buffer, index, packet, parent)

  -- Side: 1 Byte Ascii String Enum with 2 values
  index, side = b3_entrypoint_sbe_dissect.side(buffer, index, packet, parent)

  -- Single Cancel Restatement Reason: 1 Byte Unsigned Fixed Width Integer Enum with 2 values
  index, single_cancel_restatement_reason = b3_entrypoint_sbe_dissect.single_cancel_restatement_reason(buffer, index, packet, parent)

  -- Padding
  index = index + 2

  -- Sender Location: 10 Byte Ascii String
  index, sender_location = b3_entrypoint_sbe_dissect.sender_location(buffer, index, packet, parent)

  -- Entering Trader: 5 Byte Ascii String
  index, entering_trader = b3_entrypoint_sbe_dissect.entering_trader(buffer, index, packet, parent)

  -- Executing Trader Optional: 5 Byte Ascii String
  index, executing_trader_optional = b3_entrypoint_sbe_dissect.executing_trader_optional(buffer, index, packet, parent)

  -- Desk ID: 1 Byte (Length) + N Bytes
  index, desk_id = b3_entrypoint_sbe_dissect.desk_id(buffer, index, packet, parent)

  -- Memo: 1 Byte (Length) + N Bytes
  index, memo = b3_entrypoint_sbe_dissect.memo(buffer, index, packet, parent)


  return index
end

-- Dissect: Order Cancel Request Message
b3_entrypoint_sbe_dissect.order_cancel_request_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.order_cancel_request_message then
    local length = b3_entrypoint_sbe_size_of.order_cancel_request_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.order_cancel_request_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.order_cancel_request_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.order_cancel_request_message_fields(buffer, offset, packet, parent)
end

-- Size: Custody Allocation Type
b3_entrypoint_sbe_size_of.custody_allocation_type = 4

-- Display: Custody Allocation Type
b3_entrypoint_sbe_display.custody_allocation_type = function(value)
  return "Custody allocation type: "..value
end

-- Dissect: Custody Allocation Type
b3_entrypoint_sbe_dissect.custody_allocation_type = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.custody_allocation_type
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.custody_allocation_type(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.custody_allocation_type, range, value, display)

  return offset + length, value
end

-- Size: Custody Account
b3_entrypoint_sbe_size_of.custody_account = 4

-- Display: Custody Account
b3_entrypoint_sbe_display.custody_account = function(value)
  return "Custody account: "..value
end

-- Dissect: Custody Account
b3_entrypoint_sbe_dissect.custody_account = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.custody_account
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.custody_account(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.custody_account, range, value, display)

  return offset + length, value
end

-- Size: Custodian
b3_entrypoint_sbe_size_of.custodian = 4

-- Display: Custodian
b3_entrypoint_sbe_display.custodian = function(value)
  return "Custodian: "..value
end

-- Dissect: Custodian
b3_entrypoint_sbe_dissect.custodian = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.custodian
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.custodian(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.custodian, range, value, display)

  return offset + length, value
end

-- Calculate size of: Custodian Info
b3_entrypoint_sbe_size_of.custodian_info = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.custodian

  index = index + b3_entrypoint_sbe_size_of.custody_account

  index = index + b3_entrypoint_sbe_size_of.custody_allocation_type

  return index
end

-- Display: Custodian Info
b3_entrypoint_sbe_display.custodian_info = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Custodian Info
b3_entrypoint_sbe_dissect.custodian_info_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Custodian: 4 Byte Unsigned Fixed Width Integer
  index, custodian = b3_entrypoint_sbe_dissect.custodian(buffer, index, packet, parent)

  -- Custody Account: 4 Byte Unsigned Fixed Width Integer
  index, custody_account = b3_entrypoint_sbe_dissect.custody_account(buffer, index, packet, parent)

  -- Custody Allocation Type: 4 Byte Unsigned Fixed Width Integer
  index, custody_allocation_type = b3_entrypoint_sbe_dissect.custody_allocation_type(buffer, index, packet, parent)

  return index
end

-- Dissect: Custodian Info
b3_entrypoint_sbe_dissect.custodian_info = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.custodian_info then
    local length = b3_entrypoint_sbe_size_of.custodian_info(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.custodian_info(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.custodian_info, range, display)
  end

  return b3_entrypoint_sbe_dissect.custodian_info_fields(buffer, offset, packet, parent)
end

-- Size: Routing Instruction
b3_entrypoint_sbe_size_of.routing_instruction = 1

-- Display: Routing Instruction
b3_entrypoint_sbe_display.routing_instruction = function(value)
  if value == 1 then
    return "Routing instruction: RETAIL_LIQUIDITY_TAKER"
  end
  if value == 2 then
    return "Routing instruction: WAIVED_PRIORITY"
  end
  if value == 3 then
    return "Routing instruction: BROKER_ONLY"
  end
  if value == 4 then
    return "Routing instruction: BROKER_ONLY_REMOVAL"
  end
  if value == 0 then
    return "Routing instruction: NULL"
  end

  return "Routing instruction: UNKNOWN("..value..")"
end

-- Dissect: Routing Instruction
b3_entrypoint_sbe_dissect.routing_instruction = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.routing_instruction
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.routing_instruction(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.routing_instruction, range, value, display)

  return offset + length, value
end

-- Size: Time In Force Optional
b3_entrypoint_sbe_size_of.time_in_force_optional = 1

-- Display: Time In Force Optional
b3_entrypoint_sbe_display.time_in_force_optional = function(value)
  if value == "0" then
    return "Time in force: Day (0)"
  end
  if value == "1" then
    return "Time in force: Goodtillcancel (1)"
  end
  if value == "3" then
    return "Time in force: Immediateorcancel (3)"
  end
  if value == "4" then
    return "Time in force: Fillorkill (4)"
  end
  if value == "6" then
    return "Time in force: Goodtilldate (6)"
  end
  if value == "7" then
    return "Time in force: Attheclose (7)"
  end
  if value == "A" then
    return "Time in force: Goodforauction (A)"
  end
  if value == 0 then
    return "Time in force: NULL"
  end

  return "Time in force: UNKNOWN("..value..")"
end

-- Dissect: Time In Force Optional
b3_entrypoint_sbe_dissect.time_in_force_optional = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.time_in_force_optional
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()

  -- check if value is non zero
  if value == 0 then
    value = ''
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.time_in_force_optional(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.time_in_force_optional, range, value, display)

  return offset + length, value
end

-- Size: Self Trade Prevention Instruction
b3_entrypoint_sbe_size_of.self_trade_prevention_instruction = 1

-- Display: Self Trade Prevention Instruction
b3_entrypoint_sbe_display.self_trade_prevention_instruction = function(value)
  if value == 0 then
    return "Self trade prevention instruction: NONE"
  end
  if value == 1 then
    return "Self trade prevention instruction: CANCEL_AGGRESSOR_ORDER"
  end
  if value == 2 then
    return "Self trade prevention instruction: CANCEL_RESTING_ORDER"
  end
  if value == 3 then
    return "Self trade prevention instruction: CANCEL_BOTH_ORDERS"
  end

  return "Self trade prevention instruction: UNKNOWN("..value..")"
end

-- Dissect: Self Trade Prevention Instruction
b3_entrypoint_sbe_dissect.self_trade_prevention_instruction = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.self_trade_prevention_instruction
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.self_trade_prevention_instruction(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.self_trade_prevention_instruction, range, value, display)

  return offset + length, value
end

-- Size: Mm Protection Reset
b3_entrypoint_sbe_size_of.mm_protection_reset = 1

-- Display: Mm Protection Reset
b3_entrypoint_sbe_display.mm_protection_reset = function(value)
  if value == 0 then
    return "Reset market maker protection: FALSE"
  end
  if value == 1 then
    return "Reset market maker protection: TRUE"
  end

  return "Reset market maker protection: UNKNOWN("..value..")"
end

-- Dissect: Mm Protection Reset
b3_entrypoint_sbe_dissect.mm_protection_reset = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.mm_protection_reset
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.mm_protection_reset(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.mm_protection_reset, range, value, display)

  return offset + length, value
end

-- Calculate size of: Order Cancel Replace Request Message
b3_entrypoint_sbe_size_of.order_cancel_replace_request_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.inbound_business_header

  index = index + b3_entrypoint_sbe_size_of.ord_tag_id

  index = index + b3_entrypoint_sbe_size_of.mm_protection_reset

  index = index + b3_entrypoint_sbe_size_of.clordid

  index = index + b3_entrypoint_sbe_size_of.account

  index = index + b3_entrypoint_sbe_size_of.sender_location

  index = index + b3_entrypoint_sbe_size_of.entering_trader

  index = index + b3_entrypoint_sbe_size_of.self_trade_prevention_instruction

  index = index + b3_entrypoint_sbe_size_of.security_id

  index = index + b3_entrypoint_sbe_size_of.side

  index = index + b3_entrypoint_sbe_size_of.ordtype

  index = index + b3_entrypoint_sbe_size_of.time_in_force

  index = index + b3_entrypoint_sbe_size_of.routing_instruction

  index = index + b3_entrypoint_sbe_size_of.order_qty

  index = index + b3_entrypoint_sbe_size_of.price

  index = index + b3_entrypoint_sbe_size_of.order_id

  index = index + b3_entrypoint_sbe_size_of.origclordid

  index = index + b3_entrypoint_sbe_size_of.stop_px

  index = index + b3_entrypoint_sbe_size_of.min_qty

  index = index + b3_entrypoint_sbe_size_of.max_floor

  index = index + b3_entrypoint_sbe_size_of.executing_trader

  index = index + b3_entrypoint_sbe_size_of.account_type

  index = index + b3_entrypoint_sbe_size_of.expire_date

  index = index + b3_entrypoint_sbe_size_of.custodian_info(buffer, offset + index)

  index = index + b3_entrypoint_sbe_size_of.investor_id

  if version >= 3 then
    index = index + b3_entrypoint_sbe_size_of.strategy_id
  end

  index = index + b3_entrypoint_sbe_size_of.desk_id(buffer, offset + index)

  index = index + b3_entrypoint_sbe_size_of.memo(buffer, offset + index)

  return index
end

-- Display: Order Cancel Replace Request Message
b3_entrypoint_sbe_display.order_cancel_replace_request_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Order Cancel Replace Request Message
b3_entrypoint_sbe_dissect.order_cancel_replace_request_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Inbound Business Header: 1 Byte Ascii String
  index, inbound_business_header = b3_entrypoint_sbe_dissect.inbound_business_header(buffer, index, packet, parent)

  -- Ord Tag ID: 1 Byte Unsigned Fixed Width Integer
  index, ord_tag_id = b3_entrypoint_sbe_dissect.ord_tag_id(buffer, index, packet, parent)

  -- Mm Protection Reset: 1 Byte Unsigned Fixed Width Integer Enum with 2 values
  index, mm_protection_reset = b3_entrypoint_sbe_dissect.mm_protection_reset(buffer, index, packet, parent)

  -- ClOrdId: 8 Byte Unsigned Fixed Width Integer
  index, clordid = b3_entrypoint_sbe_dissect.clordid(buffer, index, packet, parent)

  -- Account: 4 Byte Unsigned Fixed Width Integer
  index, account = b3_entrypoint_sbe_dissect.account(buffer, index, packet, parent)

  -- Sender Location: 10 Byte Ascii String
  index, sender_location = b3_entrypoint_sbe_dissect.sender_location(buffer, index, packet, parent)

  -- Entering Trader: 5 Byte Ascii String
  index, entering_trader = b3_entrypoint_sbe_dissect.entering_trader(buffer, index, packet, parent)

  -- Self Trade Prevention Instruction: 1 Byte Unsigned Fixed Width Integer Enum with 4 values
  index, self_trade_prevention_instruction = b3_entrypoint_sbe_dissect.self_trade_prevention_instruction(buffer, index, packet, parent)

  -- Security ID: 8 Byte Unsigned Fixed Width Integer
  index, security_id = b3_entrypoint_sbe_dissect.security_id(buffer, index, packet, parent)

  -- Side: 1 Byte Ascii String Enum with 2 values
  index, side = b3_entrypoint_sbe_dissect.side(buffer, index, packet, parent)

  -- OrdType: 1 Byte Ascii String Enum with 7 values
  index, ordtype = b3_entrypoint_sbe_dissect.ordtype(buffer, index, packet, parent)

  -- Time In Force Optional: 1 Byte Ascii String Enum with 8 values
  index, time_in_force_optional = b3_entrypoint_sbe_dissect.time_in_force(buffer, index, packet, parent)

  -- Routing Instruction: 1 Byte Unsigned Fixed Width Integer Enum with 5 values
  index, routing_instruction = b3_entrypoint_sbe_dissect.routing_instruction(buffer, index, packet, parent)

  -- Order Qty: 8 Byte Unsigned Fixed Width Integer
  index, order_qty = b3_entrypoint_sbe_dissect.order_qty(buffer, index, packet, parent)

  -- Price Optional: 8 Byte Signed Fixed Width Integer Nullable
  index, price_optional = b3_entrypoint_sbe_dissect.price(buffer, index, packet, parent)

  -- Order ID Optional: 8 Byte Unsigned Fixed Width Integer
  index, order_id_optional = b3_entrypoint_sbe_dissect.order_id(buffer, index, packet, parent)

  -- OrigClOrdId: 8 Byte Unsigned Fixed Width Integer
  index, origclordid = b3_entrypoint_sbe_dissect.origclordid(buffer, index, packet, parent)

  -- Stop Px: 8 Byte Signed Fixed Width Integer Nullable
  index, stop_px = b3_entrypoint_sbe_dissect.stop_px(buffer, index, packet, parent)

  -- Min Qty: 8 Byte Unsigned Fixed Width Integer
  index, min_qty = b3_entrypoint_sbe_dissect.min_qty(buffer, index, packet, parent)

  -- Max Floor: 8 Byte Unsigned Fixed Width Integer
  index, max_floor = b3_entrypoint_sbe_dissect.max_floor(buffer, index, packet, parent)

  -- Executing Trader Optional: 5 Byte Ascii String
  index, executing_trader_optional = b3_entrypoint_sbe_dissect.executing_trader(buffer, index, packet, parent)

  -- Account Type: 1 Byte Unsigned Fixed Width Integer Enum with 3 values
  index, account_type = b3_entrypoint_sbe_dissect.account_type(buffer, index, packet, parent)

  -- Expire Date: 2 Byte Unsigned Fixed Width Integer
  index, expire_date = b3_entrypoint_sbe_dissect.expire_date(buffer, index, packet, parent)

  -- Custodian Info: Struct of 3 fields
  index, custodian_info = b3_entrypoint_sbe_dissect.custodian_info(buffer, index, packet, parent)

  -- Investor ID: 2 Byte (Prefix) + 2 (Padding) + 6 Byte (Document)
  index, investor_id = b3_entrypoint_sbe_dissect.investor_id(buffer, index, packet, parent)

  if version >= 3 then
    -- Strategy ID: 4 Byte Unsigned Fixed Width Integer
    index, strategy_id = b3_entrypoint_sbe_dissect.strategy_id(buffer, index, packet, parent)
  end

  -- Memo: 1 Byte (Length) + N Bytes
  index, desk_id = b3_entrypoint_sbe_dissect.desk_id(buffer, index, packet, parent)

  -- Memo: 1 Byte (Length) + N Bytes
  index, memo = b3_entrypoint_sbe_dissect.memo(buffer, index, packet, parent)

  return index
end

-- Dissect: Order Cancel Replace Request Message
b3_entrypoint_sbe_dissect.order_cancel_replace_request_message = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.order_cancel_replace_request_message(buffer, offset)
  local range = buffer(offset, length)
  local display = b3_entrypoint_sbe_display.order_cancel_replace_request_message(buffer, packet, parent)
  parent = parent:add(b3_entrypoint_sbe.fields.order_cancel_replace_request_message, range, display)

  return b3_entrypoint_sbe_dissect.order_cancel_replace_request_message_fields(buffer, offset, packet, parent)
end

-- Calculate size of: New Order Single Message
b3_entrypoint_sbe_size_of.new_order_single_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.inbound_business_header

  index = index + b3_entrypoint_sbe_size_of.ord_tag_id

  index = index + b3_entrypoint_sbe_size_of.mm_protection_reset

  index = index + b3_entrypoint_sbe_size_of.clordid

  index = index + b3_entrypoint_sbe_size_of.account

  index = index + b3_entrypoint_sbe_size_of.sender_location

  index = index + b3_entrypoint_sbe_size_of.entering_trader

  index = index + b3_entrypoint_sbe_size_of.self_trade_prevention_instruction

  index = index + b3_entrypoint_sbe_size_of.security_id

  index = index + b3_entrypoint_sbe_size_of.side

  index = index + b3_entrypoint_sbe_size_of.ordtype

  index = index + b3_entrypoint_sbe_size_of.time_in_force

  index = index + b3_entrypoint_sbe_size_of.routing_instruction

  index = index + b3_entrypoint_sbe_size_of.order_qty

  index = index + b3_entrypoint_sbe_size_of.price_optional

  index = index + b3_entrypoint_sbe_size_of.stop_px

  index = index + b3_entrypoint_sbe_size_of.min_qty

  index = index + b3_entrypoint_sbe_size_of.max_floor

  index = index + b3_entrypoint_sbe_size_of.executing_trader_optional

  index = index + b3_entrypoint_sbe_size_of.expire_date

  index = index + b3_entrypoint_sbe_size_of.custodian_info(buffer, offset + index)

  index = index + b3_entrypoint_sbe_size_of.investor_id

  index = index + b3_entrypoint_sbe_size_of.strategy_id

  index = index + b3_entrypoint_sbe_size_of.desk_id(buffer, offset + index)

  index = index + b3_entrypoint_sbe_size_of.memo(buffer, offset + index)

  return index
end

-- Display: New Order Single Message
b3_entrypoint_sbe_display.new_order_single_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: New Order Single Message
b3_entrypoint_sbe_dissect.new_order_single_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Inbound Business Header: 1 Byte Ascii String
  index, inbound_business_header = b3_entrypoint_sbe_dissect.inbound_business_header(buffer, index, packet, parent)

  -- Ord Tag ID: 1 Byte Unsigned Fixed Width Integer
  index, ord_tag_id = b3_entrypoint_sbe_dissect.ord_tag_id(buffer, index, packet, parent)

  -- Mm Protection Reset: 1 Byte Unsigned Fixed Width Integer Enum with 2 values
  index, mm_protection_reset = b3_entrypoint_sbe_dissect.mm_protection_reset(buffer, index, packet, parent)

  -- ClOrdId: 8 Byte Unsigned Fixed Width Integer
  index, clordid = b3_entrypoint_sbe_dissect.clordid(buffer, index, packet, parent)

  -- Account: 4 Byte Unsigned Fixed Width Integer
  index, account = b3_entrypoint_sbe_dissect.account(buffer, index, packet, parent)

  -- Sender Location: 10 Byte Ascii String
  index, sender_location = b3_entrypoint_sbe_dissect.sender_location(buffer, index, packet, parent)

  -- Entering Trader: 5 Byte Ascii String
  index, entering_trader = b3_entrypoint_sbe_dissect.entering_trader(buffer, index, packet, parent)

  -- Self Trade Prevention Instruction: 1 Byte Unsigned Fixed Width Integer Enum with 4 values
  index, self_trade_prevention_instruction = b3_entrypoint_sbe_dissect.self_trade_prevention_instruction(buffer, index, packet, parent)

  -- Security ID: 8 Byte Unsigned Fixed Width Integer
  index, security_id = b3_entrypoint_sbe_dissect.security_id(buffer, index, packet, parent)

  -- Side: 1 Byte Ascii String Enum with 2 values
  index, side = b3_entrypoint_sbe_dissect.side(buffer, index, packet, parent)

  -- OrdType: 1 Byte Ascii String Enum with 7 values
  index, ordtype = b3_entrypoint_sbe_dissect.ordtype(buffer, index, packet, parent)

  -- Time In Force: 1 Byte Ascii String Enum with 7 values
  index, time_in_force = b3_entrypoint_sbe_dissect.time_in_force(buffer, index, packet, parent)

  -- Routing Instruction: 1 Byte Unsigned Fixed Width Integer Enum with 5 values
  index, routing_instruction = b3_entrypoint_sbe_dissect.routing_instruction(buffer, index, packet, parent)

  -- Order Qty: 8 Byte Unsigned Fixed Width Integer
  index, order_qty = b3_entrypoint_sbe_dissect.order_qty(buffer, index, packet, parent)

  -- Price Optional: 8 Byte Signed Fixed Width Integer Nullable
  index, price_optional = b3_entrypoint_sbe_dissect.price_optional(buffer, index, packet, parent)

  -- Stop Px: 8 Byte Signed Fixed Width Integer Nullable
  index, stop_px = b3_entrypoint_sbe_dissect.stop_px(buffer, index, packet, parent)

  -- Min Qty: 8 Byte Unsigned Fixed Width Integer
  index, min_qty = b3_entrypoint_sbe_dissect.min_qty(buffer, index, packet, parent)

  -- Max Floor: 8 Byte Unsigned Fixed Width Integer
  index, max_floor = b3_entrypoint_sbe_dissect.max_floor(buffer, index, packet, parent)

  -- Executing Trader Optional: 5 Byte Ascii String
  index, executing_trader_optional = b3_entrypoint_sbe_dissect.executing_trader_optional(buffer, index, packet, parent)

  -- Expire Date: 2 Byte Unsigned Fixed Width Integer
  index, expire_date = b3_entrypoint_sbe_dissect.expire_date(buffer, index, packet, parent)

  -- Custodian Info: Struct of 3 fields
  index, custodian_info = b3_entrypoint_sbe_dissect.custodian_info(buffer, index, packet, parent)

  -- Investor ID: 2 Byte (Prefix) + 2 (Padding) + 6 Byte (Document)
  index, investor_id = b3_entrypoint_sbe_dissect.investor_id(buffer, index, packet, parent)

  -- Strategy ID: 4 Byte Unsigned Fixed Width Integer
  index, strategy_id = b3_entrypoint_sbe_dissect.strategy_id(buffer, index, packet, parent)

  -- Desk ID: 1 Byte (Length) + N Bytes
  index, desk_id = b3_entrypoint_sbe_dissect.desk_id(buffer, index, packet, parent)

  -- Memo: 1 Byte (Length) + N Bytes
  index, memo = b3_entrypoint_sbe_dissect.memo(buffer, index, packet, parent)

  return index
end

-- Dissect: New Order Single Message
b3_entrypoint_sbe_dissect.new_order_single_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.new_order_single_message then
    local length = b3_entrypoint_sbe_size_of.new_order_single_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.new_order_single_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.new_order_single_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.new_order_single_message_fields(buffer, offset, packet, parent)
end

-- Size: Time In Force Simple
b3_entrypoint_sbe_size_of.time_in_force_simple = 1

-- Display: Time In Force Simple
b3_entrypoint_sbe_display.time_in_force_simple = function(value)
  if value == 48 then
    return "Time in force: DAY"
  end
  if value == 49 then
    return "Time in force: GOOD_TILL_CANCEL (NOT VALID FOR SIMPLE NEW)"
  end
  if value == 51 then
    return "Time in force: IMMEDIATE_OR_CANCEL"
  end
  if value == 52 then
    return "Time in force: FILL_OR_KILL"
  end
  if value == 54 then
    return "Time in force: GOOD_TILL_DATE (NOT VALID FOR SIMPLE NEW)"
  end
  if value == 55  then
    return "Time in force: AT_THE_CLOSE (NOT VALID FOR SIMPLE NEW)"
  end
  if value == 65 then
    return "Time in force: GOOD_FOR_AUCTION (NOT VALID FOR SIMPLE NEW)"
  end

  return "Time in force: UNKNOWN("..value..")"
end

-- Dissect: Time In Force Simple
b3_entrypoint_sbe_dissect.time_in_force_simple = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.time_in_force_simple
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()

  local display = b3_entrypoint_sbe_display.time_in_force_simple(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.time_in_force_simple, range, value, display)

  return offset + length, value
end

-- Size: Simple OrdType
b3_entrypoint_sbe_size_of.simple_ordtype = 1

-- Display: Simple OrdType
b3_entrypoint_sbe_display.simple_ordtype = function(value)
  if value == "1" then
    return "Order type: MARKET"
  end
  if value == "2" then
    return "Order type: LIMIT"
  end

  return "Order type: UNKNOWN("..value..")"
end

-- Dissect: Simple OrdType
b3_entrypoint_sbe_dissect.simple_ordtype = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.simple_ordtype
  local range = buffer(offset, length)

  -- parse as byte
  local value = range:uint()

  -- check if value is non zero
  if value == 0 then
    value = ''
  else
    value = range:string()
  end

  local display = b3_entrypoint_sbe_display.simple_ordtype(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.simple_ordtype, range, value, display)

  return offset + length, value
end

-- Calculate size of: Simple Modify Order Message
b3_entrypoint_sbe_size_of.simple_modify_order_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.inbound_business_header

  index = index + b3_entrypoint_sbe_size_of.ord_tag_id

  index = index + b3_entrypoint_sbe_size_of.mm_protection_reset

  index = index + b3_entrypoint_sbe_size_of.clordid

  index = index + b3_entrypoint_sbe_size_of.account

  index = index + b3_entrypoint_sbe_size_of.sender_location

  index = index + b3_entrypoint_sbe_size_of.entering_trader

  index = index + b3_entrypoint_sbe_size_of.self_trade_prevention_instruction

  index = index + b3_entrypoint_sbe_size_of.security_id

  index = index + b3_entrypoint_sbe_size_of.side

  index = index + b3_entrypoint_sbe_size_of.simple_ordtype

  index = index + b3_entrypoint_sbe_size_of.time_in_force_simple

  index = index + b3_entrypoint_sbe_size_of.routing_instruction

  index = index + b3_entrypoint_sbe_size_of.order_qty

  index = index + b3_entrypoint_sbe_size_of.price_optional

  index = index + b3_entrypoint_sbe_size_of.order_id_optional

  index = index + b3_entrypoint_sbe_size_of.origclordid

  index = index + b3_entrypoint_sbe_size_of.investor_id

  index = index + b3_entrypoint_sbe_size_of.memo(buffer, offset + index)

  return index
end

-- Display: Simple Modify Order Message
b3_entrypoint_sbe_display.simple_modify_order_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Simple Modify Order Message
b3_entrypoint_sbe_dissect.simple_modify_order_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Inbound Business Header: 1 Byte Ascii String
  index, inbound_business_header = b3_entrypoint_sbe_dissect.inbound_business_header(buffer, index, packet, parent)

  -- Ord Tag ID: 1 Byte Unsigned Fixed Width Integer
  index, ord_tag_id = b3_entrypoint_sbe_dissect.ord_tag_id(buffer, index, packet, parent)

  -- Mm Protection Reset: 1 Byte Unsigned Fixed Width Integer Enum with 2 values
  index, mm_protection_reset = b3_entrypoint_sbe_dissect.mm_protection_reset(buffer, index, packet, parent)

  -- ClOrdId: 8 Byte Unsigned Fixed Width Integer
  index, clordid = b3_entrypoint_sbe_dissect.clordid(buffer, index, packet, parent)

  -- Account: 4 Byte Unsigned Fixed Width Integer
  index, account = b3_entrypoint_sbe_dissect.account(buffer, index, packet, parent)

  -- Sender Location: 10 Byte Ascii String
  index, sender_location = b3_entrypoint_sbe_dissect.sender_location(buffer, index, packet, parent)

  -- Entering Trader: 5 Byte Ascii String
  index, entering_trader = b3_entrypoint_sbe_dissect.entering_trader(buffer, index, packet, parent)

  -- Self Trade Prevention Instruction: 1 Byte Unsigned Fixed Width Integer Enum with 4 values
  index, self_trade_prevention_instruction = b3_entrypoint_sbe_dissect.self_trade_prevention_instruction(buffer, index, packet, parent)

  -- Security ID: 8 Byte Unsigned Fixed Width Integer
  index, security_id = b3_entrypoint_sbe_dissect.security_id(buffer, index, packet, parent)

  -- Side: 1 Byte Ascii String Enum with 2 values
  index, side = b3_entrypoint_sbe_dissect.side(buffer, index, packet, parent)

  -- Simple OrdType: 1 Byte Ascii String Enum with 2 values
  index, simple_ordtype = b3_entrypoint_sbe_dissect.simple_ordtype(buffer, index, packet, parent)

  -- Time In Force Simple: 1 Byte Ascii String Enum with 3 values
  index, time_in_force_simple = b3_entrypoint_sbe_dissect.time_in_force_simple(buffer, index, packet, parent)

  -- Routing Instruction: 1 Byte Unsigned Fixed Width Integer Enum with 5 values
  index, routing_instruction = b3_entrypoint_sbe_dissect.routing_instruction(buffer, index, packet, parent)

  -- Order Qty: 8 Byte Unsigned Fixed Width Integer
  index, order_qty = b3_entrypoint_sbe_dissect.order_qty(buffer, index, packet, parent)

  -- Price Optional: 8 Byte Signed Fixed Width Integer Nullable
  index, price_optional = b3_entrypoint_sbe_dissect.price_optional(buffer, index, packet, parent)

  -- Order ID Optional: 8 Byte Unsigned Fixed Width Integer
  index, order_id_optional = b3_entrypoint_sbe_dissect.order_id_optional(buffer, index, packet, parent)

  -- OrigClOrdId: 8 Byte Unsigned Fixed Width Integer
  index, origclordid = b3_entrypoint_sbe_dissect.origclordid(buffer, index, packet, parent)

  -- Investor ID: 2 Byte (Prefix) + 2 (Padding) + 6 Byte (Document)
  index, investor_id = b3_entrypoint_sbe_dissect.investor_id(buffer, index, packet, parent)

  -- Memo: 1 Byte (Length) + N Bytes
  index, memo = b3_entrypoint_sbe_dissect.memo(buffer, index, packet, parent)

  return index
end

-- Dissect: Simple Modify Order Message
b3_entrypoint_sbe_dissect.simple_modify_order_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.simple_modify_order_message then
    local length = b3_entrypoint_sbe_size_of.simple_modify_order_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.simple_modify_order_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.simple_modify_order_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.simple_modify_order_message_fields(buffer, offset, packet, parent)
end

-- Calculate size of: Simple New Order Message
b3_entrypoint_sbe_size_of.simple_new_order_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.inbound_business_header

  index = index + b3_entrypoint_sbe_size_of.ord_tag_id

  index = index + b3_entrypoint_sbe_size_of.mm_protection_reset

  index = index + b3_entrypoint_sbe_size_of.clordid

  index = index + b3_entrypoint_sbe_size_of.account

  index = index + b3_entrypoint_sbe_size_of.sender_location

  index = index + b3_entrypoint_sbe_size_of.entering_trader

  index = index + b3_entrypoint_sbe_size_of.self_trade_prevention_instruction

  index = index + b3_entrypoint_sbe_size_of.security_id

  index = index + b3_entrypoint_sbe_size_of.side

  index = index + b3_entrypoint_sbe_size_of.simple_ordtype

  index = index + b3_entrypoint_sbe_size_of.time_in_force_simple

  index = index + b3_entrypoint_sbe_size_of.routing_instruction

  index = index + b3_entrypoint_sbe_size_of.order_qty

  index = index + b3_entrypoint_sbe_size_of.price_optional

  index = index + b3_entrypoint_sbe_size_of.investor_id

  index = index + b3_entrypoint_sbe_size_of.memo(buffer, offset + index)

  return index
end

-- Display: Simple New Order Message
b3_entrypoint_sbe_display.simple_new_order_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Simple New Order Message
b3_entrypoint_sbe_dissect.simple_new_order_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Inbound Business Header: 18 Byte
  index, inbound_business_header = b3_entrypoint_sbe_dissect.inbound_business_header(buffer, index, packet, parent)

  -- Ord Tag ID: 1 Byte Unsigned Fixed Width Integer
  index, ord_tag_id = b3_entrypoint_sbe_dissect.ord_tag_id(buffer, index, packet, parent)

  -- Mm Protection Reset: 1 Byte Unsigned Fixed Width Integer Enum with 2 values
  index, mm_protection_reset = b3_entrypoint_sbe_dissect.mm_protection_reset(buffer, index, packet, parent)

  -- ClOrdId: 8 Byte Unsigned Fixed Width Integer
  index, clordid = b3_entrypoint_sbe_dissect.clordid(buffer, index, packet, parent)

  -- Account: 4 Byte Unsigned Fixed Width Integer
  index, account = b3_entrypoint_sbe_dissect.account(buffer, index, packet, parent)

  -- Sender Location: 10 Byte Ascii String
  index, sender_location = b3_entrypoint_sbe_dissect.sender_location(buffer, index, packet, parent)

  -- Entering Trader: 5 Byte Ascii String
  index, entering_trader = b3_entrypoint_sbe_dissect.entering_trader(buffer, index, packet, parent)

  -- Self Trade Prevention Instruction: 1 Byte Unsigned Fixed Width Integer Enum with 4 values
  index, self_trade_prevention_instruction = b3_entrypoint_sbe_dissect.self_trade_prevention_instruction(buffer, index, packet, parent)

  -- Security ID: 8 Byte Unsigned Fixed Width Integer
  index, security_id = b3_entrypoint_sbe_dissect.security_id(buffer, index, packet, parent)

  -- Side: 1 Byte Ascii String Enum with 2 values
  index, side = b3_entrypoint_sbe_dissect.side(buffer, index, packet, parent)

  -- Simple OrdType: 1 Byte Ascii String Enum with 2 values
  index, simple_ordtype = b3_entrypoint_sbe_dissect.simple_ordtype(buffer, index, packet, parent)

  -- Time In Force Simple: 1 Byte Ascii String Enum with 3 values
  index, time_in_force_simple = b3_entrypoint_sbe_dissect.time_in_force_simple(buffer, index, packet, parent)

  -- Routing Instruction: 1 Byte Unsigned Fixed Width Integer Enum with 5 values
  index, routing_instruction = b3_entrypoint_sbe_dissect.routing_instruction(buffer, index, packet, parent)

  -- Order Qty: 8 Byte Unsigned Fixed Width Integer
  index, order_qty = b3_entrypoint_sbe_dissect.order_qty(buffer, index, packet, parent)

  -- Price Optional: 8 Byte Signed Fixed Width Integer Nullable
  index, price_optional = b3_entrypoint_sbe_dissect.price_optional(buffer, index, packet, parent)

  -- Investor ID: 2 Byte (Prefix) + 2 (Padding) + 6 Byte (Document)
  index, investor_id = b3_entrypoint_sbe_dissect.investor_id(buffer, index, packet, parent)

  -- Memo: 1 Byte (Length) + N Bytes
  index, memo = b3_entrypoint_sbe_dissect.memo(buffer, index, packet, parent)

  return index
end

-- Dissect: Simple New Order Message
b3_entrypoint_sbe_dissect.simple_new_order_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.simple_new_order_message then
    local length = b3_entrypoint_sbe_size_of.simple_new_order_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.simple_new_order_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.simple_new_order_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.simple_new_order_message_fields(buffer, offset, packet, parent)
end

-- Size: Retransmit reject code
b3_entrypoint_sbe_size_of.retransmit_reject_code = 1

-- Display: Retransmit reject code
b3_entrypoint_sbe_display.retransmit_reject_code = function(value)
  if value == 0 then
    return "Reject code: OUT_OF_RANGE"
  end
  if value == 1 then
    return "Reject code: INVALID_SESSION"
  end
  if value == 2 then
    return "Reject code: REQUEST_LIMIT_EXCEEDED"
  end
  if value == 3 then
    return "Reject code: RETRANSMIT_IN_PROGRESS"
  end
  if value == 4 then
    return "Reject code: INVALID_TIMESTAMP"
  end
  if value == 5 then
    return "Reject code: INVALID_FROMSEQNO"
  end
  if value == 9 then
    return "Reject code: INVALID_COUNT"
  end
  if value == 10 then
    return "Reject code: THROTTLE_REJECT"
  end
  if value == 11 then
    return "Reject code: SYSTEM_BUSY"
  end

  return "Reject code: UNKNOWN("..value..")"
end

-- Dissect: Retransmit reject code
b3_entrypoint_sbe_dissect.retransmit_reject_code = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.retransmit_reject_code
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.retransmit_reject_code(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.retransmit_reject_code, range, value, display)

  return offset + length, value
end

-- Size: Request Timestamp
b3_entrypoint_sbe_size_of.request_timestamp = 8

-- Display: Request Timestamp
b3_entrypoint_sbe_display.request_timestamp = function(value)
  return "Request timestamp: "..value
end

-- Dissect: Request Timestamp
b3_entrypoint_sbe_dissect.request_timestamp = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.request_timestamp
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.request_timestamp(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.request_timestamp, range, value, display)

  return offset + length, value
end

-- Size: Session ID
b3_entrypoint_sbe_size_of.session_id = 4

-- Display: Session ID
b3_entrypoint_sbe_display.session_id = function(value)
  return "Session ID: "..value
end

-- Dissect: Session ID
b3_entrypoint_sbe_dissect.session_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.session_id
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.session_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.session_id, range, value, display)

  return offset + length, value
end

-- Calculate size of: Retransmit Reject Message
b3_entrypoint_sbe_size_of.retransmit_reject_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.session_id

  index = index + b3_entrypoint_sbe_size_of.request_timestamp

  index = index + b3_entrypoint_sbe_size_of.retransmit_reject_code

  return index
end

-- Display: Retransmit Reject Message
b3_entrypoint_sbe_display.retransmit_reject_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Retransmit Reject Message
b3_entrypoint_sbe_dissect.retransmit_reject_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Session ID: 4 Byte Unsigned Fixed Width Integer
  index, session_id = b3_entrypoint_sbe_dissect.session_id(buffer, index, packet, parent)

  -- Request Timestamp: 8 Byte Unsigned Fixed Width Integer
  index, request_timestamp = b3_entrypoint_sbe_dissect.request_timestamp(buffer, index, packet, parent)

  -- Retransmit reject code: 1 Byte Unsigned Fixed Width Integer Enum with 9 values
  index, retransmit_reject_code = b3_entrypoint_sbe_dissect.retransmit_reject_code(buffer, index, packet, parent)

  return index
end

-- Dissect: Retransmit Reject Message
b3_entrypoint_sbe_dissect.retransmit_reject_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.retransmit_reject_message then
    local length = b3_entrypoint_sbe_size_of.retransmit_reject_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.retransmit_reject_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.retransmit_reject_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.retransmit_reject_message_fields(buffer, offset, packet, parent)
end

-- Size: Count
b3_entrypoint_sbe_size_of.count = 4

-- Display: Count
b3_entrypoint_sbe_display.count = function(value)
  return "Count: "..value
end

-- Dissect: Count
b3_entrypoint_sbe_dissect.count = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.count
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.count(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.count, range, value, display)

  return offset + length, value
end

-- Size: Next Seq No
b3_entrypoint_sbe_size_of.next_seq_no = 4

-- Display: Next Seq No
b3_entrypoint_sbe_display.next_seq_no = function(value)
  return "Next sequence number: "..value
end

-- Dissect: Next Seq No
b3_entrypoint_sbe_dissect.next_seq_no = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.next_seq_no
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.next_seq_no(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.next_seq_no, range, value, display)

  return offset + length, value
end

-- Calculate size of: Retransmission Message
b3_entrypoint_sbe_size_of.retransmission_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.session_id

  index = index + b3_entrypoint_sbe_size_of.request_timestamp

  index = index + b3_entrypoint_sbe_size_of.next_seq_no

  index = index + b3_entrypoint_sbe_size_of.count

  return index
end

-- Display: Retransmission Message
b3_entrypoint_sbe_display.retransmission_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Retransmission Message
b3_entrypoint_sbe_dissect.retransmission_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Session ID: 4 Byte Unsigned Fixed Width Integer
  index, session_id = b3_entrypoint_sbe_dissect.session_id(buffer, index, packet, parent)

  -- Request Timestamp: 8 Byte Unsigned Fixed Width Integer
  index, request_timestamp = b3_entrypoint_sbe_dissect.request_timestamp(buffer, index, packet, parent)

  -- Next Seq No: 4 Byte Unsigned Fixed Width Integer
  index, next_seq_no = b3_entrypoint_sbe_dissect.next_seq_no(buffer, index, packet, parent)

  -- Count: 4 Byte Unsigned Fixed Width Integer
  index, count = b3_entrypoint_sbe_dissect.count(buffer, index, packet, parent)

  return index
end

-- Dissect: Retransmission Message
b3_entrypoint_sbe_dissect.retransmission_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.retransmission_message then
    local length = b3_entrypoint_sbe_size_of.retransmission_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.retransmission_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.retransmission_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.retransmission_message_fields(buffer, offset, packet, parent)
end

-- Size: From Seq No
b3_entrypoint_sbe_size_of.from_seq_no = 4

-- Display: From Seq No
b3_entrypoint_sbe_display.from_seq_no = function(value)
  return "From sequence number: "..value
end

-- Dissect: From Seq No
b3_entrypoint_sbe_dissect.from_seq_no = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.from_seq_no
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.from_seq_no(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.from_seq_no, range, value, display)

  return offset + length, value
end

-- Size: Timestamp
b3_entrypoint_sbe_size_of.timestamp = 8

-- Display: Timestamp
b3_entrypoint_sbe_display.timestamp = function(value)
  return "Timestamp: "..value
end

-- Dissect: Timestamp
b3_entrypoint_sbe_dissect.timestamp = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.timestamp
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.timestamp(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.timestamp, range, value, display)

  return offset + length, value
end

-- Calculate size of: Retransmit Request Message
b3_entrypoint_sbe_size_of.retransmit_request_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.session_id

  index = index + b3_entrypoint_sbe_size_of.timestamp

  index = index + b3_entrypoint_sbe_size_of.from_seq_no

  index = index + b3_entrypoint_sbe_size_of.count

  return index
end

-- Display: Retransmit Request Message
b3_entrypoint_sbe_display.retransmit_request_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Retransmit Request Message
b3_entrypoint_sbe_dissect.retransmit_request_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Session ID: 4 Byte Unsigned Fixed Width Integer
  index, session_id = b3_entrypoint_sbe_dissect.session_id(buffer, index, packet, parent)

  -- Timestamp: 8 Byte Unsigned Fixed Width Integer
  index, timestamp = b3_entrypoint_sbe_dissect.timestamp(buffer, index, packet, parent)

  -- From Seq No: 4 Byte Unsigned Fixed Width Integer
  index, from_seq_no = b3_entrypoint_sbe_dissect.from_seq_no(buffer, index, packet, parent)

  -- Count: 4 Byte Unsigned Fixed Width Integer
  index, count = b3_entrypoint_sbe_dissect.count(buffer, index, packet, parent)

  return index
end

-- Dissect: Retransmit Request Message
b3_entrypoint_sbe_dissect.retransmit_request_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.retransmit_request_message then
    local length = b3_entrypoint_sbe_size_of.retransmit_request_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.retransmit_request_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.retransmit_request_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.retransmit_request_message_fields(buffer, offset, packet, parent)
end

-- Calculate size of: Sequence Message
b3_entrypoint_sbe_size_of.sequence_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.next_seq_no

  return index
end

-- Display: Sequence Message
b3_entrypoint_sbe_display.sequence_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Sequence Message
b3_entrypoint_sbe_dissect.sequence_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Next Seq No: 4 Byte Unsigned Fixed Width Integer
  index, next_seq_no = b3_entrypoint_sbe_dissect.next_seq_no(buffer, index, packet, parent)

  return index
end

-- Dissect: Sequence Message
b3_entrypoint_sbe_dissect.sequence_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.sequence_message then
    local length = b3_entrypoint_sbe_size_of.sequence_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.sequence_message(buffer, packet, parent)

    parent = parent:add(b3_entrypoint_sbe.fields.sequence_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.sequence_message_fields(buffer, offset, packet, parent)
end

-- Calculate size of: Not Applied Message
b3_entrypoint_sbe_size_of.not_applied_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.from_seq_no

  index = index + b3_entrypoint_sbe_size_of.count

  return index
end

-- Display: Not Applied Message
b3_entrypoint_sbe_display.not_applied_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Not Applied Message
b3_entrypoint_sbe_dissect.not_applied_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- From Seq No: 4 Byte Unsigned Fixed Width Integer
  index, from_seq_no = b3_entrypoint_sbe_dissect.from_seq_no(buffer, index, packet, parent)

  -- Count: 4 Byte Unsigned Fixed Width Integer
  index, count = b3_entrypoint_sbe_dissect.count(buffer, index, packet, parent)

  return index
end

-- Dissect: Not Applied Message
b3_entrypoint_sbe_dissect.not_applied_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.not_applied_message then
    local length = b3_entrypoint_sbe_size_of.not_applied_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.not_applied_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.not_applied_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.not_applied_message_fields(buffer, offset, packet, parent)
end

-- Size: Termination Code
b3_entrypoint_sbe_size_of.termination_code = 1

-- Display: Termination Code
b3_entrypoint_sbe_display.termination_code = function(value)
  if value == 0 then
    return "Termination Code: UNSPECIFIED"
  end
  if value == 1 then
    return "Termination Code: FINISHED"
  end
  if value == 2 then
    return "Termination Code: UNNEGOTIATED"
  end
  if value == 3 then
    return "Termination Code: NOT_ESTABLISHED"
  end
  if value == 4 then
    return "Termination Code: SESSION_BLOCKED"
  end
  if value == 5 then
    return "Termination Code: NEGOTIATION_IN_PROGRESS"
  end
  if value == 6 then
    return "Termination Code: ESTABLISH_IN_PROGRESS"
  end
  if value == 10 then
    return "Termination Code: KEEPALIVE_INTERVAL_LAPSED"
  end
  if value == 11 then
    return "Termination Code: INVALID_SESSIONID"
  end
  if value == 12 then
    return "Termination Code: INVALID_SESSIONVERID"
  end
  if value == 13 then
    return "Termination Code: INVALID_TIMESTAMP"
  end
  if value == 14 then
    return "Termination Code: INVALID_NEXTSEQNO"
  end
  if value == 15 then
    return "Termination Code: UNRECOGNIZED_MESSAGE"
  end
  if value == 16 then
    return "Termination Code: INVALID_SOFH"
  end
  if value == 17 then
    return "Termination Code: DECODING_ERROR"
  end
  if value == 20 then
    return "Termination Code: TERMINATE_NOT_ALLOWED"
  end
  if value == 21 then
    return "Termination Code: TERMINATE_IN_PROGRESS"
  end
  if value == 23 then
    return "Termination Code: PROTOCOL_VERSION_NOT_SUPPORTED"
  end
  if value == 30 then
    return "Termination Code: BACKUP_TAKEOVER_IN_PROGRESS"
  end

  return "Termination Code: UNKNOWN("..value..")"
end

-- Dissect: Termination Code
b3_entrypoint_sbe_dissect.termination_code = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.termination_code
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.termination_code(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.termination_code, range, value, display)

  return offset + length, value
end

-- Size: Termination Code
b3_entrypoint_sbe_size_of.trading_session_id = 1

-- Display: Termination Code
b3_entrypoint_sbe_display.trading_session_id = function(value)
  if value == 1 then
    return "Trading Session: REGULAR_DAY_SESSION"
  end
  if value == 6 then
    return "Trading Session: NON_REGULAR_SESSION"
  end

  return "Trading Session: UNKNOWN("..value..")"
end

-- Dissect: Trading Session ID
b3_entrypoint_sbe_dissect.trading_session_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.trading_session_id
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.trading_session_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.trading_session_id, range, value, display)

  return offset + length, value
end

-- Size: Trading Session Sub ID
b3_entrypoint_sbe_size_of.trading_session_sub_id = 1

-- Display: Trading Session Sub ID
b3_entrypoint_sbe_display.trading_session_sub_id = function(value)
  if value == 2 then
    return "Instrument Group Phase: PAUSE"
  end
  if value == 4 then
    return "Instrument Group Phase: CLOSE"
  end
  if value == 17 then
    return "Instrument Group Phase: OPEN"
  end
  if value == 18 then
    return "Instrument Group Phase: PRE_CLOSE"
  end
  if value == 21 then
    return "Instrument Group Phase: PRE_OPEN"
  end
  if value == 101 then
    return "Instrument Group Phase: FINAL_CLOSING_CALL"
  end

  return "Instrument Group Phase: UNKNOWN("..value..")"
end

-- Dissect: Trading Session Sub ID
b3_entrypoint_sbe_dissect.trading_session_sub_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.trading_session_sub_id
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.trading_session_sub_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.trading_session_sub_id, range, value, display)

  return offset + length, value
end

-- Size: Trading Session Sub ID
b3_entrypoint_sbe_size_of.security_trading_status = 1

-- Display: Trading Session Sub ID
b3_entrypoint_sbe_display.security_trading_status = function(value)
  if value == 2 then
    return "Instrument Status: TRADING_HALT"
  end
  if value == 4 then
    return "Instrument Status: NO_OPEN"
  end
  if value == 17 then
    return "Instrument Status: READY_TO_TRADE"
  end
  if value == 18 then
    return "Instrument Status: FORBIDDEN"
  end
  if value == 20 then
    return "Instrument Status: UNKNOWN_OR_INVALID"
  end
  if value == 21 then
    return "Instrument Status: PRE_OPEN"
  end
  if value == 101 then
    return "Instrument Status: FINAL_CLOSING_CALL"
  end
  if value == 110 then
    return "Instrument Status: RESERVED"
  end

  return "Instrument Status: UNKNOWN("..value..")"
end

-- Dissect: Security Trading Status
b3_entrypoint_sbe_dissect.security_trading_status = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.security_trading_status
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.security_trading_status(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.security_trading_status, range, value, display)

  return offset + length, value
end

b3_entrypoint_sbe_size_of.msg_seq_num = 4
-- Dissect: Msg Seq Num
b3_entrypoint_sbe_dissect.msg_seq_num = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.msg_seq_num
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.msg_seq_num(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.msg_seq_num, range, value, display)

  return offset + length, value
end

-- Display: Msg Seq Num
b3_entrypoint_sbe_display.msg_seq_num = function(value)
  return "Sequence number: "..value
end

b3_entrypoint_sbe_size_of.strategy_id = 4
b3_entrypoint_sbe_dissect.strategy_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.strategy_id
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.strategy_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.strategy_id, range, value, display)

  return offset + length, value
end

b3_entrypoint_sbe_display.strategy_id = function(value)
  return "Strategy ID: "..value
end

b3_entrypoint_sbe_size_of.action_requested_from_session_id = 4
b3_entrypoint_sbe_dissect.action_requested_from_session_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.action_requested_from_session_id
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.action_requested_from_session_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.action_requested_from_session_id, range, value, display)

  return offset + length, value
end

b3_entrypoint_sbe_display.action_requested_from_session_id = function(value)
  return "Cancel on behalf: "..value
end

b3_entrypoint_sbe_size_of.sending_time = 8
-- Dissect: Msg Seq Num
b3_entrypoint_sbe_dissect.sending_time = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.sending_time
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.sending_time(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.sending_time, range, value, display)

  return offset + length, value
end

-- Display: Sending Time
b3_entrypoint_sbe_display.sending_time = function(value)
  return "Sending time: "..value
end

b3_entrypoint_sbe_size_of.poss_resend = 1
-- Dissect: Poss Resend
b3_entrypoint_sbe_dissect.poss_resend = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.poss_resend
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.poss_resend(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.poss_resend, range, value, display)

  return offset + length + 1, value
end

-- Display: Sending Time
b3_entrypoint_sbe_display.poss_resend = function(value)
  if value == 0 then
    return "Possible resend: FALSE"
  end

  if value == 1 then
    return "Possible resend: TRUE"
  end

  return "Possible resend: UNKNOWN("..value..")"
end

b3_entrypoint_sbe_size_of.market_segment_id = 1
-- Dissect: Msg Seq Num
b3_entrypoint_sbe_dissect.market_segment_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.market_segment_id
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.market_segment_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.market_segment_id, range, value, display)

  return offset + length, value
end

-- Display: Sending Time
b3_entrypoint_sbe_display.market_segment_id = function(value)
  return "Market segment ID: "..value
end

-- Size: Session Ver ID
b3_entrypoint_sbe_size_of.session_ver_id = 8

-- Display: Session Ver ID
b3_entrypoint_sbe_display.session_ver_id = function(value)
  return "Session version ID: "..value
end


-- Dissect: Session Ver ID
b3_entrypoint_sbe_dissect.session_ver_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.session_ver_id
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.session_ver_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.session_ver_id, range, value, display)

  return offset + length, value
end

-- Calculate size of: Terminate Message
b3_entrypoint_sbe_size_of.terminate_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.session_id

  index = index + b3_entrypoint_sbe_size_of.session_ver_id

  index = index + b3_entrypoint_sbe_size_of.termination_code

  return index
end

-- Display: Terminate Message
b3_entrypoint_sbe_display.terminate_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Terminate Message
b3_entrypoint_sbe_dissect.terminate_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Session ID: 4 Byte Unsigned Fixed Width Integer
  index, session_id = b3_entrypoint_sbe_dissect.session_id(buffer, index, packet, parent)

  -- Session Ver ID: 8 Byte Unsigned Fixed Width Integer
  index, session_ver_id = b3_entrypoint_sbe_dissect.session_ver_id(buffer, index, packet, parent)

  -- Termination Code: 1 Byte Unsigned Fixed Width Integer Enum with 19 values
  index, termination_code = b3_entrypoint_sbe_dissect.termination_code(buffer, index, packet, parent)

  return index
end

-- Dissect: Terminate Message
b3_entrypoint_sbe_dissect.terminate_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.terminate_message then
    local length = b3_entrypoint_sbe_size_of.terminate_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.terminate_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.terminate_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.terminate_message_fields(buffer, offset, packet, parent)
end

-- Size: Last Incoming Seq No Optional
b3_entrypoint_sbe_size_of.last_incoming_seq_no_optional = 4

-- Display: Last Incoming Seq No Optional
b3_entrypoint_sbe_display.last_incoming_seq_no_optional = function(value)
  return "Last incoming sequence number: "..value
end

-- Dissect: Last Incoming Seq No Optional
b3_entrypoint_sbe_dissect.last_incoming_seq_no_optional = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.last_incoming_seq_no_optional
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.last_incoming_seq_no_optional(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.last_incoming_seq_no_optional, range, value, display)

  return offset + length, value
end

-- Size: Establishment reject code
b3_entrypoint_sbe_size_of.establishment_reject_code = 1

-- Display: Establishment reject code
b3_entrypoint_sbe_display.establishment_reject_code = function(value)
  if value == 0 then
    return "Reject code: UNSPECIFIED"
  end
  if value == 1 then
    return "Reject code: CREDENTIALS"
  end
  if value == 2 then
    return "Reject code: UNNEGOTIATED"
  end
  if value == 3 then
    return "Reject code: ALREADY_ESTABLISHED"
  end
  if value == 4 then
    return "Reject code: SESSION_BLOCKED"
  end
  if value == 5 then
    return "Reject code: INVALID_SESSIONID"
  end
  if value == 6 then
    return "Reject code: INVALID_SESSIONVERID"
  end
  if value == 7 then
    return "Reject code: INVALID_TIMESTAMP"
  end
  if value == 8 then
    return "Reject code: INVALID_KEEPALIVE_INTERVAL"
  end
  if value == 9 then
    return "Reject code: INVALID_NEXTSEQNO"
  end
  if value == 10 then
    return "Reject code: ESTABLISH_ATTEMPTS_EXCEEDED"
  end
  if value == 20 then
    return "Reject code: ESTABLISH_NOT_ALLOWED"
  end
  if value == 21 then
    return "Reject code:DUPLICATE_SESSION_CONNECTION"
  end
  if value == 22 then
    return "Reject code: AUTHENTICATION_IN_PROGRESS"
  end
  if value == 23 then
    return "Reject code: PROTOCOL_VERSION_NOT_SUPPORTED"
  end

  return "Reject code: UNKNOWN("..value..")"
end

-- Dissect: Establishment reject code
b3_entrypoint_sbe_dissect.establishment_reject_code = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.establishment_reject_code
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.establishment_reject_code(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.establishment_reject_code, range, value, display)

  return offset + length, value
end

-- Calculate size of: Establish Reject Message
b3_entrypoint_sbe_size_of.establish_reject_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.session_id

  index = index + b3_entrypoint_sbe_size_of.session_ver_id

  index = index + b3_entrypoint_sbe_size_of.request_timestamp

  index = index + b3_entrypoint_sbe_size_of.establishment_reject_code

  -- Padding 1 Byte
  index = index + 1

  index = index + b3_entrypoint_sbe_size_of.last_incoming_seq_no_optional

  return index
end

-- Display: Establish Reject Message
b3_entrypoint_sbe_display.establish_reject_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Establish Reject Message
b3_entrypoint_sbe_dissect.establish_reject_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Session ID: 4 Byte Unsigned Fixed Width Integer
  index, session_id = b3_entrypoint_sbe_dissect.session_id(buffer, index, packet, parent)

  -- Session Ver ID: 8 Byte Unsigned Fixed Width Integer
  index, session_ver_id = b3_entrypoint_sbe_dissect.session_ver_id(buffer, index, packet, parent)

  -- Request Timestamp: 8 Byte Unsigned Fixed Width Integer
  index, request_timestamp = b3_entrypoint_sbe_dissect.request_timestamp(buffer, index, packet, parent)

  -- Establishment reject code: 1 Byte Unsigned Fixed Width Integer Enum with 15 values
  index, establishment_reject_code = b3_entrypoint_sbe_dissect.establishment_reject_code(buffer, index, packet, parent)

  -- Padding 1 Byte
  index = index + 1

  -- Last Incoming Seq No Optional: 4 Byte Unsigned Fixed Width Integer
  index, last_incoming_seq_no_optional = b3_entrypoint_sbe_dissect.last_incoming_seq_no_optional(buffer, index, packet, parent)

  return index
end

-- Dissect: Establish Reject Message
b3_entrypoint_sbe_dissect.establish_reject_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.establish_reject_message then
    local length = b3_entrypoint_sbe_size_of.establish_reject_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.establish_reject_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.establish_reject_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.establish_reject_message_fields(buffer, offset, packet, parent)
end

-- Size: Last Incoming Seq No
b3_entrypoint_sbe_size_of.last_incoming_seq_no = 4

-- Display: Last Incoming Seq No
b3_entrypoint_sbe_display.last_incoming_seq_no = function(value)
  return "Last Incoming Seq No: "..value
end

-- Dissect: Last Incoming Seq No
b3_entrypoint_sbe_dissect.last_incoming_seq_no = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.last_incoming_seq_no
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.last_incoming_seq_no(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.last_incoming_seq_no, range, value, display)

  return offset + length, value
end

-- Size: Keep Alive Interval
b3_entrypoint_sbe_size_of.keep_alive_interval = 8

-- Display: Keep Alive Interval
b3_entrypoint_sbe_display.keep_alive_interval = function(value)
  return "Keep alive interval (ms): "..value
end

-- Dissect: Keep Alive Interval
b3_entrypoint_sbe_dissect.keep_alive_interval = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.keep_alive_interval
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.keep_alive_interval(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.keep_alive_interval, range, value, display)

  return offset + length, value
end

-- Calculate size of: Establish Ack Message
b3_entrypoint_sbe_size_of.establish_ack_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.session_id

  index = index + b3_entrypoint_sbe_size_of.session_ver_id

  index = index + b3_entrypoint_sbe_size_of.request_timestamp

  index = index + b3_entrypoint_sbe_size_of.keep_alive_interval

  index = index + b3_entrypoint_sbe_size_of.next_seq_no

  index = index + b3_entrypoint_sbe_size_of.last_incoming_seq_no

  return index
end

-- Display: Establish Ack Message
b3_entrypoint_sbe_display.establish_ack_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Establish Ack Message
b3_entrypoint_sbe_dissect.establish_ack_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Session ID: 4 Byte Unsigned Fixed Width Integer
  index, session_id = b3_entrypoint_sbe_dissect.session_id(buffer, index, packet, parent)

  -- Session Ver ID: 8 Byte Unsigned Fixed Width Integer
  index, session_ver_id = b3_entrypoint_sbe_dissect.session_ver_id(buffer, index, packet, parent)

  -- Request Timestamp: 8 Byte Unsigned Fixed Width Integer
  index, request_timestamp = b3_entrypoint_sbe_dissect.request_timestamp(buffer, index, packet, parent)

  -- Keep Alive Interval: 8 Byte Unsigned Fixed Width Integer
  index, keep_alive_interval = b3_entrypoint_sbe_dissect.keep_alive_interval(buffer, index, packet, parent)

  -- Next Seq No: 4 Byte Unsigned Fixed Width Integer
  index, next_seq_no = b3_entrypoint_sbe_dissect.next_seq_no(buffer, index, packet, parent)

  -- Last Incoming Seq No: 4 Byte Unsigned Fixed Width Integer
  index, last_incoming_seq_no = b3_entrypoint_sbe_dissect.last_incoming_seq_no(buffer, index, packet, parent)

  return index
end

-- Dissect: Establish Ack Message
b3_entrypoint_sbe_dissect.establish_ack_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.establish_ack_message then
    local length = b3_entrypoint_sbe_size_of.establish_ack_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.establish_ack_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.establish_ack_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.establish_ack_message_fields(buffer, offset, packet, parent)
end


-- Calculate size of variable data
b3_entrypoint_sbe_size_of.variable_data = function(buffer, offset)
  local end_of_payload = buffer:len()

  if end_of_payload < offset + 1 then
    return 0
  end

  return buffer(offset, 1):le_uint() + 1
end

-- Calculate size of: Memo
b3_entrypoint_sbe_size_of.memo = function(buffer, offset)
  return b3_entrypoint_sbe_size_of.variable_data(buffer, offset)
end

-- Calculate size of: Memo
b3_entrypoint_sbe_size_of.desk_id = function(buffer, offset)
  return b3_entrypoint_sbe_size_of.variable_data(buffer, offset)
end

-- Calculate size of: Credentials
b3_entrypoint_sbe_size_of.credentials = function(buffer, offset)
  return b3_entrypoint_sbe_size_of.variable_data(buffer, offset)
end

-- Display: Credentials
b3_entrypoint_sbe_display.credentials = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Credentials
b3_entrypoint_sbe_dissect.credentials_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Length: 1 Byte Unsigned Fixed Width Integer
  index, length = b3_entrypoint_sbe_dissect.length(buffer, index, packet, parent)

  -- Var Data char
  index, var_data_char = b3_entrypoint_sbe_dissect.var_data_char(buffer, index, packet, parent, length)

  return index
end

-- Dissect: Credentials
b3_entrypoint_sbe_dissect.credentials = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.credentials then
    local length = b3_entrypoint_sbe_size_of.credentials(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.credentials(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.credentials, range, display)
  end

  return b3_entrypoint_sbe_dissect.credentials_fields(buffer, offset, packet, parent)
end

-- Display: Memo
b3_entrypoint_sbe_display.memo = function(buffer, offset, size, packet, parent)
  return ""
end

-- Display: Memo
b3_entrypoint_sbe_display.desk_id = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Memo
b3_entrypoint_sbe_dissect.memo_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Length: 1 Byte Unsigned Fixed Width Integer
  index, length = b3_entrypoint_sbe_dissect.length(buffer, index, packet, parent)

  -- Var Data char
  index, var_data_char = b3_entrypoint_sbe_dissect.var_data_char(buffer, index, packet, parent, length)

  return index
end

-- Dissect Fields: Memo
b3_entrypoint_sbe_dissect.desk_id_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Length: 1 Byte Unsigned Fixed Width Integer
  index, length = b3_entrypoint_sbe_dissect.length(buffer, index, packet, parent)

  -- Var Data char
  index, var_data_char = b3_entrypoint_sbe_dissect.var_data_char(buffer, index, packet, parent, length)

  return index
end

-- Dissect: Desk ID
b3_entrypoint_sbe_dissect.desk_id = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.desk_id then
    local length = b3_entrypoint_sbe_size_of.desk_id(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.desk_id(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.desk_id, range, display)
  end

  return b3_entrypoint_sbe_dissect.desk_id_fields(buffer, offset, packet, parent)
end


-- Dissect: Memo
b3_entrypoint_sbe_dissect.memo = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.memo then
    local length = b3_entrypoint_sbe_size_of.memo(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.memo(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.memo, range, display)
  end

  return b3_entrypoint_sbe_dissect.memo_fields(buffer, offset, packet, parent)
end


-- Size: Cod Timeout Window
b3_entrypoint_sbe_size_of.cod_timeout_window = 8

-- Display: Cod Timeout Window
b3_entrypoint_sbe_display.cod_timeout_window = function(value)
  return "Cancel on disconnect timeout window (ms): "..value
end

-- Dissect: Cod Timeout Window
b3_entrypoint_sbe_dissect.cod_timeout_window = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.cod_timeout_window
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.cod_timeout_window(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.cod_timeout_window, range, value, display)

  return offset + length, value
end

-- Size: Cancel On Disconnect Type
b3_entrypoint_sbe_size_of.cancel_on_disconnect_type = 1

-- Display: Cancel On Disconnect Type
b3_entrypoint_sbe_display.cancel_on_disconnect_type = function(value)
  if value == 0 then
    return "Cancel on disconnect type: DO_NOT_CANCEL_ON_DISCONNECT_OR_TERMINATE"
  end
  if value == 1 then
    return "Cancel on disconnect type: CANCEL_ON_DISCONNECT_ONLY"
  end
  if value == 2 then
    return "Cancel on disconnect type: CANCEL_ON_TERMINATE_ONLY"
  end
  if value == 3 then
    return "Cancel on disconnect type: CANCEL_ON_DISCONNECT_OR_TERMINATE"
  end

  return "Cancel on disconnect type: UNKNOWN("..value..")"
end

-- Dissect: Cancel On Disconnect Type
b3_entrypoint_sbe_dissect.cancel_on_disconnect_type = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.cancel_on_disconnect_type
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.cancel_on_disconnect_type(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.cancel_on_disconnect_type, range, value, display)

  return offset + length, value
end

-- Calculate size of: Establish Message
b3_entrypoint_sbe_size_of.establish_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.session_id

  index = index + b3_entrypoint_sbe_size_of.session_ver_id

  index = index + b3_entrypoint_sbe_size_of.timestamp

  index = index + b3_entrypoint_sbe_size_of.keep_alive_interval

  index = index + b3_entrypoint_sbe_size_of.next_seq_no

  index = index + b3_entrypoint_sbe_size_of.cancel_on_disconnect_type

  -- Padding 1 Byte
  index = index + 1

  index = index + b3_entrypoint_sbe_size_of.cod_timeout_window

  index = index + b3_entrypoint_sbe_size_of.credentials(buffer, offset + index)

  return index
end

-- Display: Establish Message
b3_entrypoint_sbe_display.establish_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Establish Message
b3_entrypoint_sbe_dissect.establish_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Session ID: 4 Byte Unsigned Fixed Width Integer
  index, session_id = b3_entrypoint_sbe_dissect.session_id(buffer, index, packet, parent)

  -- Session Ver ID: 8 Byte Unsigned Fixed Width Integer
  index, session_ver_id = b3_entrypoint_sbe_dissect.session_ver_id(buffer, index, packet, parent)

  -- Timestamp: 8 Byte Unsigned Fixed Width Integer
  index, timestamp = b3_entrypoint_sbe_dissect.timestamp(buffer, index, packet, parent)

  -- Keep Alive Interval: 8 Byte Unsigned Fixed Width Integer
  index, keep_alive_interval = b3_entrypoint_sbe_dissect.keep_alive_interval(buffer, index, packet, parent)

  -- Next Seq No: 4 Byte Unsigned Fixed Width Integer
  index, next_seq_no = b3_entrypoint_sbe_dissect.next_seq_no(buffer, index, packet, parent)

  -- Cancel On Disconnect Type: 1 Byte Unsigned Fixed Width Integer Enum with 4 values
  index, cancel_on_disconnect_type = b3_entrypoint_sbe_dissect.cancel_on_disconnect_type(buffer, index, packet, parent)

  -- Padding 1 Byte
  index = index + 1

  -- Cod Timeout Window: 8 Byte Unsigned Fixed Width Integer
  index, cod_timeout_window = b3_entrypoint_sbe_dissect.cod_timeout_window(buffer, index, packet, parent)

  -- Credentials: Struct of 2 fields
  index, credentials = b3_entrypoint_sbe_dissect.credentials(buffer, index, packet, parent)

  return index
end

-- Dissect: Establish Message
b3_entrypoint_sbe_dissect.establish_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.establish_message then
    local length = b3_entrypoint_sbe_size_of.establish_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.establish_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.establish_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.establish_message_fields(buffer, offset, packet, parent)
end

-- Size: Current Session Ver ID
b3_entrypoint_sbe_size_of.current_session_ver_id = 8

-- Display: Current Session Ver ID
b3_entrypoint_sbe_display.current_session_ver_id = function(value)
  return "Current session version ID: "..value
end

-- Dissect: Current Session Ver ID
b3_entrypoint_sbe_dissect.current_session_ver_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.current_session_ver_id
  local range = buffer(offset, length)
  local value = range:le_uint64()
  local display = b3_entrypoint_sbe_display.current_session_ver_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.current_session_ver_id, range, value, display)

  return offset + length, value
end

-- Size: Negotiation reject code
b3_entrypoint_sbe_size_of.negotiation_reject_code = 1

-- Display: Negotiation reject code
b3_entrypoint_sbe_display.negotiation_reject_code = function(value)
  if value == 0 then
    return "Reject code: UNSPECIFIED"
  end
  if value == 1 then
    return "Reject code: CREDENTIALS"
  end
  if value == 2 then
    return "Reject code: FLOWTYPE_NOT_SUPPORTED"
  end
  if value == 3 then
    return "Reject code: ALREADY_NEGOTIATED"
  end
  if value == 4 then
    return "Reject code: SESSION_BLOCKED"
  end
  if value == 5 then
    return "Reject code: INVALID_SESSIONID"
  end
  if value == 6 then
    return "Reject code: INVALID_SESSIONVERID"
  end
  if value == 7 then
    return "Reject code: INVALID_TIMESTAMP"
  end
  if value == 8 then
    return "Reject code: INVALID_FIRM"
  end
  if value == 20 then
    return "Reject code: NEGOTIATE_NOT_ALLOWED"
  end
  if value == 21 then
    return "Reject code: DUPLICATE_SESSION_CONNECTION"
  end
  if value == 22 then
    return "Reject code: AUTHENTICATION_IN_PROGRESS"
  end
  if value == 23 then
    return "Reject code: PROTOCOL_VERSION_NOT_SUPPORTED"
  end

  return "Reject code: UNKNOWN("..value..")"
end

-- Dissect: Negotiation reject code
b3_entrypoint_sbe_dissect.negotiation_reject_code = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.negotiation_reject_code
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.negotiation_reject_code(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.negotiation_reject_code, range, value, display)

  return offset + length, value
end

-- Calculate size of: Negotiate Reject Message
b3_entrypoint_sbe_size_of.negotiate_reject_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.session_id

  index = index + b3_entrypoint_sbe_size_of.session_ver_id

  index = index + b3_entrypoint_sbe_size_of.request_timestamp

  index = index + b3_entrypoint_sbe_size_of.entering_firm_optional

  index = index + b3_entrypoint_sbe_size_of.negotiation_reject_code

  -- Padding 3 Bytes
  index = index + 3

  index = index + b3_entrypoint_sbe_size_of.current_session_ver_id

  return index
end

-- Display: Negotiate Reject Message
b3_entrypoint_sbe_display.negotiate_reject_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Negotiate Reject Message
b3_entrypoint_sbe_dissect.negotiate_reject_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Session ID: 4 Byte Unsigned Fixed Width Integer
  index, session_id = b3_entrypoint_sbe_dissect.session_id(buffer, index, packet, parent)

  -- Session Ver ID: 8 Byte Unsigned Fixed Width Integer
  index, session_ver_id = b3_entrypoint_sbe_dissect.session_ver_id(buffer, index, packet, parent)

  -- Request Timestamp: 8 Byte Unsigned Fixed Width Integer
  index, request_timestamp = b3_entrypoint_sbe_dissect.request_timestamp(buffer, index, packet, parent)

  -- Entering Firm Optional: 4 Byte Unsigned Fixed Width Integer
  index, entering_firm_optional = b3_entrypoint_sbe_dissect.entering_firm_optional(buffer, index, packet, parent)

  -- Negotiation reject code: 1 Byte Unsigned Fixed Width Integer Enum with 13 values
  index, negotiation_reject_code = b3_entrypoint_sbe_dissect.negotiation_reject_code(buffer, index, packet, parent)

  -- Padding 3 Bytes
  index = index + 3

  -- Current Session Ver ID: 8 Byte Unsigned Fixed Width Integer
  index, current_session_ver_id = b3_entrypoint_sbe_dissect.current_session_ver_id(buffer, index, packet, parent)

  return index
end

-- Dissect: Negotiate Reject Message
b3_entrypoint_sbe_dissect.negotiate_reject_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.negotiate_reject_message then
    local length = b3_entrypoint_sbe_size_of.negotiate_reject_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.negotiate_reject_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.negotiate_reject_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.negotiate_reject_message_fields(buffer, offset, packet, parent)
end

-- Size: Entering Firm
b3_entrypoint_sbe_size_of.entering_firm = 4

-- Display: Entering Firm
b3_entrypoint_sbe_display.entering_firm = function(value)
  return "Entering firm: "..value
end

-- Dissect: Entering Firm
b3_entrypoint_sbe_dissect.entering_firm = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.entering_firm
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.entering_firm(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.entering_firm, range, value, display)

  return offset + length, value
end

-- Calculate size of: Negotiate Response Message
b3_entrypoint_sbe_size_of.negotiate_response_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.session_id

  index = index + b3_entrypoint_sbe_size_of.session_ver_id

  index = index + b3_entrypoint_sbe_size_of.request_timestamp

  index = index + b3_entrypoint_sbe_size_of.entering_firm

  return index
end

-- Display: Negotiate Response Message
b3_entrypoint_sbe_display.negotiate_response_message = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Negotiate Response Message
b3_entrypoint_sbe_dissect.negotiate_response_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Session ID: 4 Byte Unsigned Fixed Width Integer
  index, session_id = b3_entrypoint_sbe_dissect.session_id(buffer, index, packet, parent)

  -- Session Ver ID: 8 Byte Unsigned Fixed Width Integer
  index, session_ver_id = b3_entrypoint_sbe_dissect.session_ver_id(buffer, index, packet, parent)

  -- Request Timestamp: 8 Byte Unsigned Fixed Width Integer
  index, request_timestamp = b3_entrypoint_sbe_dissect.request_timestamp(buffer, index, packet, parent)

  -- Entering Firm: 4 Byte Unsigned Fixed Width Integer
  index, entering_firm = b3_entrypoint_sbe_dissect.entering_firm(buffer, index, packet, parent)

  return index
end

-- Dissect: Negotiate Response Message
b3_entrypoint_sbe_dissect.negotiate_response_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.negotiate_response_message then
    local length = b3_entrypoint_sbe_size_of.negotiate_response_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.negotiate_response_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.negotiate_response_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.negotiate_response_message_fields(buffer, offset, packet, parent)
end

-- Calculate size of: Client App Version
b3_entrypoint_sbe_size_of.client_app_version = function(buffer, offset)
  return b3_entrypoint_sbe_size_of.variable_data(buffer, offset)
end

-- Display: Client App Version
b3_entrypoint_sbe_display.client_app_version = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Client App Version
b3_entrypoint_sbe_dissect.client_app_version_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Length: 1 Byte Unsigned Fixed Width Integer
  index, length = b3_entrypoint_sbe_dissect.length(buffer, index, packet, parent)

  -- Var Data char
  index, var_data_char = b3_entrypoint_sbe_dissect.var_data_char(buffer, index, packet, parent, length)

  return index
end

-- Dissect: Client App Version
b3_entrypoint_sbe_dissect.client_app_version = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.client_app_version then
    local length = b3_entrypoint_sbe_size_of.client_app_version(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.client_app_version(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.client_app_version, range, display)
  end

  return b3_entrypoint_sbe_dissect.client_app_version_fields(buffer, offset, packet, parent)
end

-- Calculate size of: Client App Name
b3_entrypoint_sbe_size_of.client_app_name = function(buffer, offset)
  return b3_entrypoint_sbe_size_of.variable_data(buffer, offset)
end

-- Display: Client App Name
b3_entrypoint_sbe_display.client_app_name = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Client App Name
b3_entrypoint_sbe_dissect.client_app_name_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Length: 1 Byte Unsigned Fixed Width Integer
  index, length = b3_entrypoint_sbe_dissect.length(buffer, index, packet, parent)

  -- Var Data char
  index, var_data_char = b3_entrypoint_sbe_dissect.var_data_char(buffer, index, packet, parent, length)

  return index
end

-- Dissect: Client App Name
b3_entrypoint_sbe_dissect.client_app_name = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.client_app_name then
    local length = b3_entrypoint_sbe_size_of.client_app_name(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.client_app_name(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.client_app_name, range, display)
  end

  return b3_entrypoint_sbe_dissect.client_app_name_fields(buffer, offset, packet, parent)
end

-- Calculate size of: Client Ip
b3_entrypoint_sbe_size_of.client_ip = function(buffer, offset)
  return b3_entrypoint_sbe_size_of.variable_data(buffer, offset)
end

-- Display: Client Ip
b3_entrypoint_sbe_display.client_ip = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Client Ip
b3_entrypoint_sbe_dissect.client_ip_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Length: 1 Byte Unsigned Fixed Width Integer
  index, length = b3_entrypoint_sbe_dissect.length(buffer, index, packet, parent)

  -- Var Data char
  index, var_data_char = b3_entrypoint_sbe_dissect.var_data_char(buffer, index, packet, parent, length)

  return index
end

-- Dissect: Client Ip
b3_entrypoint_sbe_dissect.client_ip = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.client_ip then
    local length = b3_entrypoint_sbe_size_of.client_ip(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.client_ip(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.client_ip, range, display)
  end

  return b3_entrypoint_sbe_dissect.client_ip_fields(buffer, offset, packet, parent)
end

-- Size: Onbehalf Firm
b3_entrypoint_sbe_size_of.onbehalf_firm = 4

-- Display: Onbehalf Firm
b3_entrypoint_sbe_display.onbehalf_firm = function(value)
  return "Onbehalf firm: "..value
end

-- Dissect: Onbehalf Firm
b3_entrypoint_sbe_dissect.onbehalf_firm = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.onbehalf_firm
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.onbehalf_firm(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.onbehalf_firm, range, value, display)

  return offset + length, value
end

-- Calculate size of: Negotiate Message
b3_entrypoint_sbe_size_of.negotiate_message = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.session_id

  index = index + b3_entrypoint_sbe_size_of.session_ver_id

  index = index + b3_entrypoint_sbe_size_of.timestamp

  index = index + b3_entrypoint_sbe_size_of.entering_firm

  index = index + b3_entrypoint_sbe_size_of.onbehalf_firm

  index = index + b3_entrypoint_sbe_size_of.credentials(buffer, offset + index)

  index = index + b3_entrypoint_sbe_size_of.client_ip(buffer, offset + index)

  index = index + b3_entrypoint_sbe_size_of.client_app_name(buffer, offset + index)

  index = index + b3_entrypoint_sbe_size_of.client_app_version(buffer, offset + index)

  return index
end

-- Display: Negotiate Message
b3_entrypoint_sbe_display.negotiate_message = function(buffer, offset, size, packet, parent)
  return ""
end


-- Dissect Fields: Negotiate Message
b3_entrypoint_sbe_dissect.negotiate_message_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Session ID: 4 Byte Unsigned Fixed Width Integer
  index, session_id = b3_entrypoint_sbe_dissect.session_id(buffer, index, packet, parent)

  -- Session Ver ID: 8 Byte Unsigned Fixed Width Integer
  index, session_ver_id = b3_entrypoint_sbe_dissect.session_ver_id(buffer, index, packet, parent)

  -- Timestamp: 8 Byte Unsigned Fixed Width Integer
  index, timestamp = b3_entrypoint_sbe_dissect.timestamp(buffer, index, packet, parent)

  -- Entering Firm: 4 Byte Unsigned Fixed Width Integer
  index, entering_firm = b3_entrypoint_sbe_dissect.entering_firm(buffer, index, packet, parent)

  -- Onbehalf Firm: 4 Byte Unsigned Fixed Width Integer
  index, onbehalf_firm = b3_entrypoint_sbe_dissect.onbehalf_firm(buffer, index, packet, parent)

  -- Credentials: Struct of 2 fields
  index, credentials = b3_entrypoint_sbe_dissect.credentials(buffer, index, packet, parent)

  -- Client Ip: Struct of 2 fields
  index, client_ip = b3_entrypoint_sbe_dissect.client_ip(buffer, index, packet, parent)

  -- Client App Name: Struct of 2 fields
  index, client_app_name = b3_entrypoint_sbe_dissect.client_app_name(buffer, index, packet, parent)

  -- Client App Version: Struct of 2 fields
  index, client_app_version = b3_entrypoint_sbe_dissect.client_app_version(buffer, index, packet, parent)

  return index
end

-- Dissect: Negotiate Message
b3_entrypoint_sbe_dissect.negotiate_message = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.negotiate_message then
    local length = b3_entrypoint_sbe_size_of.negotiate_message(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.negotiate_message(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.negotiate_message, range, display)
  end

  return b3_entrypoint_sbe_dissect.negotiate_message_fields(buffer, offset, packet, parent)
end

-- Calculate runtime size of: Payload
b3_entrypoint_sbe_size_of.payload = function(buffer, offset, template_id)
  -- Size of Negotiate Message
  if template_id == 1 then
    return b3_entrypoint_sbe_size_of.negotiate_message(buffer, offset)
  end
  -- Size of Negotiate Response Message
  if template_id == 2 then
    return b3_entrypoint_sbe_size_of.negotiate_response_message(buffer, offset)
  end
  -- Size of Negotiate Reject Message
  if template_id == 3 then
    return b3_entrypoint_sbe_size_of.negotiate_reject_message(buffer, offset)
  end
  -- Size of Establish Message
  if template_id == 4 then
    return b3_entrypoint_sbe_size_of.establish_message(buffer, offset)
  end
  -- Size of Establish Ack Message
  if template_id == 5 then
    return b3_entrypoint_sbe_size_of.establish_ack_message(buffer, offset)
  end
  -- Size of Establish Reject Message
  if template_id == 6 then
    return b3_entrypoint_sbe_size_of.establish_reject_message(buffer, offset)
  end
  -- Size of Terminate Message
  if template_id == 7 then
    return b3_entrypoint_sbe_size_of.terminate_message(buffer, offset)
  end
  -- Size of Not Applied Message
  if template_id == 8 then
    return b3_entrypoint_sbe_size_of.not_applied_message(buffer, offset)
  end
  -- Size of Sequence Message
  if template_id == 9 then
    return b3_entrypoint_sbe_size_of.sequence_message(buffer, offset)
  end
  -- Size of Retransmit Request Message
  if template_id == 12 then
    return b3_entrypoint_sbe_size_of.retransmit_request_message(buffer, offset)
  end
  -- Size of Retransmission Message
  if template_id == 13 then
    return b3_entrypoint_sbe_size_of.retransmission_message(buffer, offset)
  end
  -- Size of Retransmit Reject Message
  if template_id == 14 then
    return b3_entrypoint_sbe_size_of.retransmit_reject_message(buffer, offset)
  end
  -- Size of Simple New Order Message
  if template_id == 100 then
    return b3_entrypoint_sbe_size_of.simple_new_order_message(buffer, offset)
  end
  -- Size of Simple Modify Order Message
  if template_id == 101 then
    return b3_entrypoint_sbe_size_of.simple_modify_order_message(buffer, offset)
  end
  -- Size of New Order Single Message
  if template_id == 102 then
    return b3_entrypoint_sbe_size_of.new_order_single_message(buffer, offset)
  end
  -- Size of Order Cancel Replace Request Message
  if template_id == 104 then
    return b3_entrypoint_sbe_size_of.order_cancel_replace_request_message(buffer, offset)
  end
  -- Size of Order Cancel Request Message
  if template_id == 105 then
    return b3_entrypoint_sbe_size_of.order_cancel_request_message(buffer, offset)
  end
  -- Size of New Order Cross Message
  if template_id == 106 then
    return b3_entrypoint_sbe_size_of.new_order_cross_message(buffer, offset)
  end
  -- Size of Execution Report New Message
  if template_id == 200 then
    return b3_entrypoint_sbe_size_of.execution_report_new_message(buffer, offset)
  end
  -- Size of Execution Report Modify Message
  if template_id == 201 then
    return b3_entrypoint_sbe_size_of.execution_report_modify_message(buffer, offset)
  end
  -- Size of Execution Report Cancel Message
  if template_id == 202 then
    return b3_entrypoint_sbe_size_of.execution_report_cancel_message(buffer, offset)
  end
  -- Size of Execution Report Trade Message
  if template_id == 203 then
    return b3_entrypoint_sbe_size_of.execution_report_trade_message(buffer, offset)
  end
  -- Size of Execution Report Reject Message
  if template_id == 204 then
    return b3_entrypoint_sbe_size_of.execution_report_reject_message(buffer, offset)
  end
  -- Size of Execution Report Forward Message
  if template_id == 205 then
    return b3_entrypoint_sbe_size_of.execution_report_forward_message(buffer, offset)
  end
  -- Size of Business Message Reject
  if template_id == 206 then
    return b3_entrypoint_sbe_size_of.business_message_reject(buffer, offset)
  end
  -- Size of Security Definition Request Message
  if template_id == 300 then
    return b3_entrypoint_sbe_size_of.security_definition_request_message(buffer, offset)
  end
  -- Size of Security Definition Response Message
  if template_id == 301 then
    return b3_entrypoint_sbe_size_of.security_definition_response_message(buffer, offset)
  end
  -- Size of Quote Request Message
  if template_id == 401 then
    return b3_entrypoint_sbe_size_of.quote_request_message(buffer, offset)
  end
  -- Size of Quote Status Report Message
  if template_id == 402 then
    return b3_entrypoint_sbe_size_of.quote_status_report_message(buffer, offset)
  end
  -- Size of Quote Message
  if template_id == 403 then
    return b3_entrypoint_sbe_size_of.quote_message(buffer, offset)
  end
  -- Size of Quote Cancel Message
  if template_id == 404 then
    return b3_entrypoint_sbe_size_of.quote_cancel_message(buffer, offset)
  end
  -- Size of Quote Request Reject Message
  if template_id == 405 then
    return b3_entrypoint_sbe_size_of.quote_request_reject_message(buffer, offset)
  end
  -- Size of Position Maintenance Cancel Request Message
  if template_id == 501 then
    return b3_entrypoint_sbe_size_of.position_maintenance_cancel_request_message(buffer, offset)
  end
  -- Size of Position Maintenance Request Message
  if template_id == 502 then
    return b3_entrypoint_sbe_size_of.position_maintenance_request_message(buffer, offset)
  end
  -- Size of Position Maintenance Report Message
  if template_id == 503 then
    return b3_entrypoint_sbe_size_of.position_maintenance_report_message(buffer, offset)
  end
  -- Size of Allocation Instruction Message
  if template_id == 601 then
    return b3_entrypoint_sbe_size_of.allocation_instruction_message(buffer, offset)
  end
  -- Size of Allocation Report Message
  if template_id == 602 then
    return b3_entrypoint_sbe_size_of.allocation_report_message(buffer, offset)
  end
  -- Size of Order Mass Action Request Message
  if template_id == 701 then
    return b3_entrypoint_sbe_size_of.order_mass_action_request_message(buffer, offset)
  end
  -- Size of Order Mass Action Report Message
  if template_id == 702 then
    return b3_entrypoint_sbe_size_of.order_mass_action_report_message(buffer, offset)
  end
  -- Size of Header Message
  if template_id == 0 then
    return b3_entrypoint_sbe_size_of.header_message(buffer, offset)
  end

  return 0
end

-- Display: Payload
b3_entrypoint_sbe_display.payload = function(buffer, offset, packet, parent)
  return ""
end

-- Dissect Branches: Payload
b3_entrypoint_sbe_dissect.payload_branches = function(buffer, offset, packet, parent, template_id)
  -- Dissect Negotiate Message
  if template_id == 1 then
    return b3_entrypoint_sbe_dissect.negotiate_message(buffer, offset, packet, parent)
  end
  -- Dissect Negotiate Response Message
  if template_id == 2 then
    return b3_entrypoint_sbe_dissect.negotiate_response_message(buffer, offset, packet, parent)
  end
  -- Dissect Negotiate Reject Message
  if template_id == 3 then
    return b3_entrypoint_sbe_dissect.negotiate_reject_message(buffer, offset, packet, parent)
  end
  -- Dissect Establish Message
  if template_id == 4 then
    return b3_entrypoint_sbe_dissect.establish_message(buffer, offset, packet, parent)
  end
  -- Dissect Establish Ack Message
  if template_id == 5 then
    return b3_entrypoint_sbe_dissect.establish_ack_message(buffer, offset, packet, parent)
  end
  -- Dissect Establish Reject Message
  if template_id == 6 then
    return b3_entrypoint_sbe_dissect.establish_reject_message(buffer, offset, packet, parent)
  end
  -- Dissect Terminate Message
  if template_id == 7 then
    return b3_entrypoint_sbe_dissect.terminate_message(buffer, offset, packet, parent)
  end
  -- Dissect Not Applied Message
  if template_id == 8 then
    return b3_entrypoint_sbe_dissect.not_applied_message(buffer, offset, packet, parent)
  end
  -- Dissect Sequence Message
  if template_id == 9 then
    return b3_entrypoint_sbe_dissect.sequence_message(buffer, offset, packet, parent)
  end
  -- Dissect Retransmit Request Message
  if template_id == 12 then
    return b3_entrypoint_sbe_dissect.retransmit_request_message(buffer, offset, packet, parent)
  end
  -- Dissect Retransmission Message
  if template_id == 13 then
    return b3_entrypoint_sbe_dissect.retransmission_message(buffer, offset, packet, parent)
  end
  -- Dissect Retransmit Reject Message
  if template_id == 14 then
    return b3_entrypoint_sbe_dissect.retransmit_reject_message(buffer, offset, packet, parent)
  end
  -- Dissect Simple New Order Message
  if template_id == 100 then
    return b3_entrypoint_sbe_dissect.simple_new_order_message(buffer, offset, packet, parent)
  end
  -- Dissect Simple Modify Order Message
  if template_id == 101 then
    return b3_entrypoint_sbe_dissect.simple_modify_order_message(buffer, offset, packet, parent)
  end
  -- Dissect New Order Single Message
  if template_id == 102 then
    return b3_entrypoint_sbe_dissect.new_order_single_message(buffer, offset, packet, parent)
  end
  -- Dissect Order Cancel Replace Request Message
  if template_id == 104 then
    return b3_entrypoint_sbe_dissect.order_cancel_replace_request_message(buffer, offset, packet, parent)
  end
  -- Dissect Order Cancel Request Message
  if template_id == 105 then
    return b3_entrypoint_sbe_dissect.order_cancel_request_message(buffer, offset, packet, parent)
  end
  -- Dissect New Order Cross Message
  if template_id == 106 then
    return b3_entrypoint_sbe_dissect.new_order_cross_message(buffer, offset, packet, parent)
  end
  -- Dissect Execution Report New Message
  if template_id == 200 then
    return b3_entrypoint_sbe_dissect.execution_report_new_message(buffer, offset, packet, parent)
  end
  -- Dissect Execution Report Modify Message
  if template_id == 201 then
    return b3_entrypoint_sbe_dissect.execution_report_modify_message(buffer, offset, packet, parent)
  end
  -- Dissect Execution Report Cancel Message
  if template_id == 202 then
    return b3_entrypoint_sbe_dissect.execution_report_cancel_message(buffer, offset, packet, parent)
  end
  -- Dissect Execution Report Trade Message
  if template_id == 203 then
    return b3_entrypoint_sbe_dissect.execution_report_trade_message(buffer, offset, packet, parent)
  end
  -- Dissect Execution Report Reject Message
  if template_id == 204 then
    return b3_entrypoint_sbe_dissect.execution_report_reject_message(buffer, offset, packet, parent)
  end
  -- Dissect Execution Report Forward Message
  if template_id == 205 then
    return b3_entrypoint_sbe_dissect.execution_report_forward_message(buffer, offset, packet, parent)
  end
  -- Dissect Business Message Reject
  if template_id == 206 then
    return b3_entrypoint_sbe_dissect.business_message_reject(buffer, offset, packet, parent)
  end
  -- Dissect Security Definition Request Message
  if template_id == 300 then
    return b3_entrypoint_sbe_dissect.security_definition_request_message(buffer, offset, packet, parent)
  end
  -- Dissect Security Definition Response Message
  if template_id == 301 then
    return b3_entrypoint_sbe_dissect.security_definition_response_message(buffer, offset, packet, parent)
  end
  -- Dissect Quote Request Message
  if template_id == 401 then
    return b3_entrypoint_sbe_dissect.quote_request_message(buffer, offset, packet, parent)
  end
  -- Dissect Quote Status Report Message
  if template_id == 402 then
    return b3_entrypoint_sbe_dissect.quote_status_report_message(buffer, offset, packet, parent)
  end
  -- Dissect Quote Message
  if template_id == 403 then
    return b3_entrypoint_sbe_dissect.quote_message(buffer, offset, packet, parent)
  end
  -- Dissect Quote Cancel Message
  if template_id == 404 then
    return b3_entrypoint_sbe_dissect.quote_cancel_message(buffer, offset, packet, parent)
  end
  -- Dissect Quote Request Reject Message
  if template_id == 405 then
    return b3_entrypoint_sbe_dissect.quote_request_reject_message(buffer, offset, packet, parent)
  end
  -- Dissect Position Maintenance Cancel Request Message
  if template_id == 501 then
    return b3_entrypoint_sbe_dissect.position_maintenance_cancel_request_message(buffer, offset, packet, parent)
  end
  -- Dissect Position Maintenance Request Message
  if template_id == 502 then
    return b3_entrypoint_sbe_dissect.position_maintenance_request_message(buffer, offset, packet, parent)
  end
  -- Dissect Position Maintenance Report Message
  if template_id == 503 then
    return b3_entrypoint_sbe_dissect.position_maintenance_report_message(buffer, offset, packet, parent)
  end
  -- Dissect Allocation Instruction Message
  if template_id == 601 then
    return b3_entrypoint_sbe_dissect.allocation_instruction_message(buffer, offset, packet, parent)
  end
  -- Dissect Allocation Report Message
  if template_id == 602 then
    return b3_entrypoint_sbe_dissect.allocation_report_message(buffer, offset, packet, parent)
  end
  -- Dissect Order Mass Action Request Message
  if template_id == 701 then
    return b3_entrypoint_sbe_dissect.order_mass_action_request_message(buffer, offset, packet, parent)
  end
  -- Dissect Order Mass Action Report Message
  if template_id == 702 then
    return b3_entrypoint_sbe_dissect.order_mass_action_report_message(buffer, offset, packet, parent)
  end
  -- Dissect Header Message
  if template_id == 0 then
    return b3_entrypoint_sbe_dissect.header_message(buffer, offset, packet, parent)
  end

  return offset
end

-- Dissect: Payload
b3_entrypoint_sbe_dissect.payload = function(buffer, offset, packet, parent, template_id)
  if not show.payload then
    return b3_entrypoint_sbe_dissect.payload_branches(buffer, offset, packet, parent, template_id)
  end

  -- Calculate size and check that branch is not empty
  local size = b3_entrypoint_sbe_size_of.payload(buffer, offset, template_id)
  if size == 0 then
    return offset
  end

  -- Dissect Element
  local range = buffer(offset, size)
  local display = b3_entrypoint_sbe_display.payload(buffer, packet, parent)
  local element = parent:add(b3_entrypoint_sbe.fields.payload, range, display)

  return b3_entrypoint_sbe_dissect.payload_branches(buffer, offset, packet, parent, template_id)
end

-- Size: Version
b3_entrypoint_sbe_size_of.version = 2

-- Display: Version
b3_entrypoint_sbe_display.version = function(value)
  return "Version: "..value
end

-- Dissect: Version
b3_entrypoint_sbe_dissect.version = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.version
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.version(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.version, range, value, display)

  return offset + length, value
end

-- Size: Schema ID
b3_entrypoint_sbe_size_of.schema_id = 2

-- Display: Schema ID
b3_entrypoint_sbe_display.schema_id = function(value)
  return "Schema ID: "..value
end

-- Dissect: Schema ID
b3_entrypoint_sbe_dissect.schema_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.schema_id
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.schema_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.schema_id, range, value, display)

  return offset + length, value
end

-- Size: Template ID
b3_entrypoint_sbe_size_of.template_id = 2

-- Display: Template ID
b3_entrypoint_sbe_display.template_id = function(value)
  if value == 1 then
    return "Template ID: Negotiate (1)"
  end
  if value == 2 then
    return "Template ID: Negotiate Response (2)"
  end
  if value == 3 then
    return "Template ID: Negotiate Reject (3)"
  end
  if value == 4 then
    return "Template ID: Establish (4)"
  end
  if value == 5 then
    return "Template ID: Establish Ack (5)"
  end
  if value == 6 then
    return "Template ID: Establish Reject (6)"
  end
  if value == 7 then
    return "Template ID: Terminate (7)"
  end
  if value == 8 then
    return "Template ID: Not Applied (8)"
  end
  if value == 9 then
    return "Template ID: Sequence (9)"
  end
  if value == 12 then
    return "Template ID: Retransmit Request (12)"
  end
  if value == 13 then
    return "Template ID: Retransmission (13)"
  end
  if value == 14 then
    return "Template ID: Retransmit Reject (14)"
  end
  if value == 100 then
    return "Template ID: Simple New Order (100)"
  end
  if value == 101 then
    return "Template ID: Simple Modify Order (101)"
  end
  if value == 102 then
    return "Template ID: New Order Single (102)"
  end
  if value == 104 then
    return "Template ID: Order Cancel Replace Request (104)"
  end
  if value == 105 then
    return "Template ID: Order Cancel Request (105)"
  end
  if value == 106 then
    return "Template ID: New Order Cross (106)"
  end
  if value == 200 then
    return "Template ID: Execution Report New (200)"
  end
  if value == 201 then
    return "Template ID: Execution Report Modify (201)"
  end
  if value == 202 then
    return "Template ID: Execution Report Cancel (202)"
  end
  if value == 203 then
    return "Template ID: Execution Report Trade (203)"
  end
  if value == 204 then
    return "Template ID: Execution Report Reject (204)"
  end
  if value == 205 then
    return "Template ID: Execution Report Forward (205)"
  end
  if value == 206 then
    return "Template ID: Business Message (206)"
  end
  if value == 300 then
    return "Template ID: Security Definition Request (300)"
  end
  if value == 301 then
    return "Template ID: Security Definition Response (301)"
  end
  if value == 401 then
    return "Template ID: Quote Request (401)"
  end
  if value == 402 then
    return "Template ID: Quote Status Report (402)"
  end
  if value == 403 then
    return "Template ID: Quote (403)"
  end
  if value == 404 then
    return "Template ID: Quote Cancel (404)"
  end
  if value == 405 then
    return "Template ID: Quote Request Reject (405)"
  end
  if value == 501 then
    return "Template ID: Position Maintenance Cancel Request (501)"
  end
  if value == 502 then
    return "Template ID: Position Maintenance Request (502)"
  end
  if value == 503 then
    return "Template ID: Position Maintenance Report (503)"
  end
  if value == 601 then
    return "Template ID: Allocation Instruction (601)"
  end
  if value == 602 then
    return "Template ID: Allocation Report (602)"
  end
  if value == 701 then
    return "Template ID: Order Mass Action Request (701)"
  end
  if value == 702 then
    return "Template ID: Order Mass Action Report (702)"
  end
  if value == 0 then
    return "Template ID: Header Message (0)"
  end

  return "Template ID: UNKNOWN("..value..")"
end

-- Dissect: Template ID
b3_entrypoint_sbe_dissect.template_id = function(buffer, offset, packet, parent)
  local length = b3_entrypoint_sbe_size_of.template_id
  local range = buffer(offset, length)
  local value = range:le_uint()
  local display = b3_entrypoint_sbe_display.template_id(value, buffer, offset, packet, parent)

  parent:add(b3_entrypoint_sbe.fields.template_id, range, value, display)

  return offset + length, value
end

-- Calculate size of: Message Header
b3_entrypoint_sbe_size_of.message_header = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.block_length

  index = index + b3_entrypoint_sbe_size_of.template_id

  index = index + b3_entrypoint_sbe_size_of.schema_id

  index = index + b3_entrypoint_sbe_size_of.version

  return index
end

-- Display: Message Header
b3_entrypoint_sbe_display.message_header = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Message Header
b3_entrypoint_sbe_dissect.message_header_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Block Length: 2 Byte Unsigned Fixed Width Integer
  index, block_length = b3_entrypoint_sbe_dissect.block_length(buffer, index, packet, parent)

  -- Template ID: 2 Byte Unsigned Fixed Width Integer Enum with 40 values
  index, template_id = b3_entrypoint_sbe_dissect.template_id(buffer, index, packet, parent)

  -- Schema ID: 2 Byte Unsigned Fixed Width Integer Static
  index, schema_id = b3_entrypoint_sbe_dissect.schema_id(buffer, index, packet, parent)

  -- Version: 2 Byte Unsigned Fixed Width Integer Static
  index, version = b3_entrypoint_sbe_dissect.version(buffer, index, packet, parent)

  return index
end

-- Dissect: Message Header
b3_entrypoint_sbe_dissect.message_header = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.message_header then
    local length = b3_entrypoint_sbe_size_of.message_header(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.message_header(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.message_header, range, display)
  end

  return b3_entrypoint_sbe_dissect.message_header_fields(buffer, offset, packet, parent)
end

-- Calculate size of: Simple Open Framing Header
b3_entrypoint_sbe_size_of.simple_open_framing_header = function(buffer, offset)
  local index = 0

  index = index + b3_entrypoint_sbe_size_of.message_length

  index = index + b3_entrypoint_sbe_size_of.encoding_type

  return index
end

-- Display: Simple Open Framing Header
b3_entrypoint_sbe_display.simple_open_framing_header = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Simple Open Framing Header
b3_entrypoint_sbe_dissect.simple_open_framing_header_fields = function(buffer, offset, packet, parent)
  local index = offset

  -- Message Length: 2 Byte Unsigned Fixed Width Integer
  index, message_length = b3_entrypoint_sbe_dissect.message_length(buffer, index, packet, parent)

  -- Encoding Type: 2 Byte Unsigned Fixed Width Integer
  index, encoding_type = b3_entrypoint_sbe_dissect.encoding_type(buffer, index, packet, parent)

  return index
end

-- Dissect: Simple Open Framing Header
b3_entrypoint_sbe_dissect.simple_open_framing_header = function(buffer, offset, packet, parent)
  -- Optionally add struct element to protocol tree
  if show.simple_open_framing_header then
    local length = b3_entrypoint_sbe_size_of.simple_open_framing_header(buffer, offset)
    local range = buffer(offset, length)
    local display = b3_entrypoint_sbe_display.simple_open_framing_header(buffer, packet, parent)
    parent = parent:add(b3_entrypoint_sbe.fields.simple_open_framing_header, range, display)
  end

  return b3_entrypoint_sbe_dissect.simple_open_framing_header_fields(buffer, offset, packet, parent)
end

-- Display: Simple Open Frame
b3_entrypoint_sbe_display.simple_open_frame = function(buffer, offset, size, packet, parent)
  return ""
end

-- Dissect Fields: Simple Open Frame
b3_entrypoint_sbe_dissect.simple_open_frame_fields = function(buffer, offset, packet, parent, size_of_simple_open_frame)
  local index = offset

  -- Simple Open Framing Header: Struct of 2 fields
  index, simple_open_framing_header = b3_entrypoint_sbe_dissect.simple_open_framing_header(buffer, index, packet, parent)

  -- Dependency element: Template ID
  local template_id = buffer(index + 2, 2):le_uint()

  -- Message Header: Struct of 4 fields
  index, message_header = b3_entrypoint_sbe_dissect.message_header(buffer, index, packet, parent)

  -- Payload: Runtime Type with 40 branches
  index = b3_entrypoint_sbe_dissect.payload(buffer, index, packet, parent, template_id)

  return index
end

-- Dissect: Simple Open Frame
b3_entrypoint_sbe_dissect.simple_open_frame = function(buffer, offset, packet, parent, size_of_simple_open_frame)


  b3_entrypoint_sbe_dissect.simple_open_frame_fields(buffer, offset, packet, parent, size_of_simple_open_frame)

  return offset + size_of_simple_open_frame
end

-- Remaining Bytes For: Simple Open Frame
local simple_open_frame_bytes_remaining = function(buffer, index, available)
  -- Calculate the number of bytes remaining
  local remaining = available - index

  -- Check if packet size can be read
  if remaining < b3_entrypoint_sbe_size_of.simple_open_framing_header(buffer, index) then
    return -DESEGMENT_ONE_MORE_SEGMENT
  end

  -- Parse runtime size
  local current = buffer(index, 2):le_uint()

  -- Check if enough bytes remain
  if remaining < current then
    return -(current - remaining)
  end

  return remaining, current
end

-- Dissect Packet
b3_entrypoint_sbe_dissect.packet = function(buffer, packet, parent)
  local index = 0

  -- Dependency for Simple Open Frame
  local end_of_payload = buffer:len()

  -- Simple Open Frame: Struct of 3 fields
  while index < end_of_payload do

    -- Are minimum number of bytes are available?
    local available, size_of_simple_open_frame = simple_open_frame_bytes_remaining(buffer, index, end_of_payload)

    if available > 0 then
      index = b3_entrypoint_sbe_dissect.simple_open_frame(buffer, index, packet, parent, size_of_simple_open_frame)
    else
      -- More bytes needed, so set packet information
      packet.desegment_offset = index
      packet.desegment_len = -(available)

      break
    end
  end

  return index
end


-----------------------------------------------------------------------
-- Protocol Dissector and Components
-----------------------------------------------------------------------

-- Initialize Dissector
function b3_entrypoint_sbe.init()
end

-- Dissector for B3 Equities BinaryEntryPoint Sbe 8.0
function b3_entrypoint_sbe.dissector(buffer, packet, parent)

  -- Set protocol name
  packet.cols.protocol = b3_entrypoint_sbe.name

  -- Dissect protocol
  local protocol = parent:add(b3_entrypoint_sbe, buffer(), b3_entrypoint_sbe.description, "("..buffer:len().." Bytes)")
  return b3_entrypoint_sbe_dissect.packet(buffer, packet, protocol)
end

-- Register With Tcp Table
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(65333, b3_entrypoint_sbe)


-----------------------------------------------------------------------
-- Protocol Heuristics
-----------------------------------------------------------------------

-- Verify size of packet
verify.b3_entrypoint_sbe_packet_size = function(buffer)

  return true
end

-- Verify Schema ID Field
verify.schema_id = function(buffer)
  -- Attempt to read field
  local value = buffer(8, 2):le_uint()
  return value == 1
end

-- Verify Version Field
verify.version = function(buffer)
  -- Attempt to read field
  local value = buffer(10, 2):le_uint()
  return value >= 1 and value <= 255
end

-- Dissector Heuristic for B3 Equities BinaryEntryPoint Sbe 8.0
local function b3_entrypoint_sbe_heuristic(buffer, packet, parent)
  -- Verify packet length
  if not verify.b3_entrypoint_sbe_packet_size(buffer) then return false end

  -- Verify Schema ID
  if not verify.schema_id(buffer) then return false end

  -- Verify Version
  if not verify.version(buffer) then return false end

  -- Protocol is valid, set conversation and dissect this packet
  packet.conversation = b3_entrypoint_sbe
  b3_entrypoint_sbe.dissector(buffer, packet, parent)

  return true
end

-- Register Heuristic for B3 Equities BinaryEntryPoint Sbe 8.0
b3_entrypoint_sbe:register_heuristic("tcp", b3_entrypoint_sbe_heuristic)
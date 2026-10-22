import 'dart:typed_data';

import 'package:proxypin/network/channel/channel.dart';
import 'package:proxypin/network/channel/channel_context.dart';
import 'package:proxypin/network/components/ws_control.dart';
import 'package:proxypin/network/http/http.dart';
import 'package:proxypin/network/http/websocket.dart';
import 'package:proxypin/network/util/logger.dart';

/// websocket处理器
class WebSocketChannelHandler extends ChannelHandler<Uint8List> {
  final WebSocketDecoder decoder = WebSocketDecoder();

  final Channel proxyChannel;
  final HttpMessage message;

  WebSocketChannelHandler(this.proxyChannel, this.message);

  /// 该处理器负责的方向：`true` 为服务端→客户端，`false` 为客户端→服务端。
  bool get toClient => message is HttpRequest;

  @override
  Future<void> channelRead(ChannelContext channelContext, Channel channel, Uint8List msg) async {
    var control = WebSocketControl.instance;
    var id = message.requestId;
    var currentMessage = message;
    HttpRequest? request = currentMessage is HttpRequest
        ? currentMessage
        : (currentMessage is HttpResponse ? currentMessage.request : null);
    control.attach(id, proxyChannel,
        toClient: toClient, request: request, context: channelContext, listener: channelContext.listener);

    if (control.rules(id).isEmpty) {
      proxyChannel.writeBytes(msg);
      _drain(channelContext, channel, msg);
      return;
    }

    // 有改写规则时不能先转发原始字节：先解码，改完再编码发送。未收齐的半个帧
    // 留在 decoder.buffer 里等下一次读取，避免把半帧透传出去导致对端解析错位。
    var frames = <WebSocketFrame>[];
    Uint8List chunk = msg;
    while (true) {
      WebSocketFrame? frame;
      try {
        frame = decoder.decode(chunk);
      } catch (e, stackTrace) {
        log.e("websocket decode error", error: e, stackTrace: stackTrace);
        break;
      }
      if (frame == null) break;
      frame.isFromClient = message is HttpRequest;
      frames.add(frame);
      chunk = _empty;
    }
    if (frames.isEmpty) return;

    var output = BytesBuilder();
    for (var frame in frames) {
      var rewritten = control.rewrite(frame, id, toClient: toClient);
      output.add(rewritten ??
          WebSocketControl.encodeFrame(
              opcode: frame.opcode, payload: frame.payloadData, mask: frame.mask, fin: frame.fin));
    }
    proxyChannel.writeBytes(output.takeBytes());

    for (var frame in frames) {
      message.messages.add(frame);
      channelContext.listener?.onMessage(channel, message, frame);
      logger.d(
          "[${channelContext.clientChannel?.id}] websocket channelRead ${frame.payloadLength} ${frame.fin} ${frame.payloadDataAsString}");
    }
  }

  void _drain(ChannelContext channelContext, Channel channel, Uint8List msg) {
    // A single TCP read may carry multiple WebSocket frames (Nagle, TLS record
    // batching, OS coalescing). Drain the decoder until no more full frames
    // remain in its buffer; subsequent iterations pass empty bytes so we only
    // consume what is already buffered.
    Uint8List chunk = msg;
    while (true) {
      WebSocketFrame? frame;
      try {
        frame = decoder.decode(chunk);
      } catch (e, stackTrace) {
        log.e("websocket decode error", error: e, stackTrace: stackTrace);
        break;
      }
      if (frame == null) break;
      frame.isFromClient = message is HttpRequest;

      message.messages.add(frame);
      channelContext.listener?.onMessage(channel, message, frame);
      logger.d(
          "[${channelContext.clientChannel?.id}] websocket channelRead ${frame.payloadLength} ${frame.fin} ${frame.payloadDataAsString}");

      chunk = _empty;
    }
  }

  @override
  void channelInactive(ChannelContext channelContext, Channel channel) {
    WebSocketControl.instance.detach(message.requestId, toClient: toClient);
  }

  static final Uint8List _empty = Uint8List(0);
}

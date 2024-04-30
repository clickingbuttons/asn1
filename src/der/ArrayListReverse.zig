/// ArrayList(u8) that grows from the end of its allocated slice rather than the beginning.
/// Useful for prefix length encoding.
/// capacity  |--------------------------|
/// data                   |-------------|
data: []u8,
capacity: usize,
allocator: Allocator,

pub fn init(allocator: Allocator) Self {
    return .{ .data = &.{}, .capacity = 0, .allocator = allocator };
}

pub fn deinit(self: *Self) void {
    self.allocator.free(self.allocatedSlice());
}

fn allocatedSlice(self: *Self) []u8 {
    return (self.data.ptr + self.data.len - self.capacity)[0..self.capacity];
}

pub fn ensureCapacity(self: *Self, new_capacity: usize) !void {
    if (self.capacity >= new_capacity) return;

    const old_memory = self.allocatedSlice();
    // Just make a new allocation to not worry about aliasing.
    const new_memory = try self.allocator.alloc(u8, new_capacity);
    @memcpy(new_memory[new_capacity - self.data.len ..], self.data);
    self.allocator.free(old_memory);
    self.data.ptr = new_memory.ptr + new_capacity - self.data.len;
    self.capacity = new_memory.len;
}

pub fn prependSlice(self: *Self, data: []const u8) !void {
    try self.ensureCapacity(self.data.len + data.len);
    const old_len = self.data.len;
    const new_len = old_len + data.len;
    assert(new_len <= self.capacity);
    self.data.len = new_len;

    const end = self.data.ptr;
    const begin = end - data.len;
    const slice = begin[0..data.len];
    @memcpy(slice, data);
    self.data.ptr = begin;
}

pub fn prependByte(self: *Self, value: u8) !void {
    return self.prependSlice(&[_]u8{value});
}

/// Invalidates all element pointers.
pub fn clearAndFree(self: *Self) void {
    self.allocator.free(self.allocatedSlice());
    self.data.len = 0;
    self.capacity = 0;
}

/// The caller owns the returned memory.
/// Capacity is cleared, making deinit() safe but unnecessary to call.
pub fn toOwnedSlice(self: *Self) ![]u8 {
    const new_memory = try self.allocator.alloc(u8, self.data.len);
    @memcpy(new_memory, self.data);
    @memset(self.data, undefined);
    self.clearAndFree();
    return new_memory;
}

pub const Writer = std.io.Writer(*Self, Allocator.Error, prependWrite);

pub fn writer(self: *Self) Writer {
    return .{ .context = self };
}

fn prependWrite(self: *Self, m: []const u8) Allocator.Error!usize {
    try self.prependSlice(m);
    return m.len;
}

test Self {
    var b = Self.init(testing.allocator);
    defer b.deinit();
    const data: []const u8 = &.{ 4, 5, 6 };
    try b.prependSlice(data);
    try testing.expectEqual(@as(usize, data.len), b.data.len);
    try testing.expectEqualSlices(u8, data, b.data);

    const data2: []const u8 = &.{ 1, 2, 3 };
    try b.prependSlice(data2);
    try testing.expectEqual(@as(usize, data.len + data2.len), b.data.len);
    try testing.expectEqualSlices(u8, data2 ++ data, b.data);

    const data3: u8 = 0;
    try b.prependByte(data3);
    try testing.expectEqual(@as(usize, data.len + data2.len + 1), b.data.len);
    try testing.expectEqualSlices(u8, [_]u8{data3} ++ data2 ++ data, b.data);
}

const std = @import("std");

const Self = @This();
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const testing = std.testing;


//
//  ViewController.m
//  BSBacktraceLogger
//
//  Created by 张星宇 on 16/8/26.
//  Copyright © 2016年 bestswifter. All rights reserved.
//



#import "ViewController.h"
#import "BSBacktraceLogger.h"
#import "JYCallStack.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)foo {
    [self bar];
}

- (void)bar {
    int i= 0;
    while (i < 1000000000)
    {
        i++;

    }
//
    
//    sleep(1000);
    
    [self test7];
}

- (void)test1 {
    [self test2];
}

- (void)test2 {
    [self test3];
}

- (void)test3 {
    [self test4];
}

- (void)test4 {
    [self test5];
}

- (void)test5 {
//    [self foo];
    [self test6];
}

- (void)test6 {
    [self foo];
}

- (void)test7 {
    [self test8];
}

- (void)test8 {
//    [BSBacktraceLogger bs_backtraceOfCurrentThread];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        BSLOG_MAIN  // 打印主线程调用栈， BSLOG 打印当前线程，BSLOG_ALL 打印所有线程
        // 调用 [BSBacktraceLogger bs_backtraceOfCurrentThread] 这一系列的方法可以获取字符串，然后选择上传服务器或者其他处理。
//        [JYCallStack callStackWithThread:JYCallStackTypeAllThread];
    });
    [self test1];
}

@end

// kernel.cu
extern "C" __global__ void recover_kernel(
    void* tasks_ptr,
    unsigned int tasks_len,
    void* target_ptr,
    void* result_ptr
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < tasks_len) {
        ((unsigned char*)result_ptr)[idx] = 0;
    }
}
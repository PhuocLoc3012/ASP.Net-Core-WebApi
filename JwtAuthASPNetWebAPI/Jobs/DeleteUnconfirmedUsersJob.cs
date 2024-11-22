using JwtAuthASPNetWebAPI.Core.Interfaces;
using Quartz;

namespace JwtAuthASPNetWebAPI.Jobs
{
    public class DeleteUnconfirmedUsersJob : IJob
    {

        private readonly IUserService _userService;
        public DeleteUnconfirmedUsersJob(IUserService userService)
        {
            _userService = userService;
        }

        public async Task Execute(IJobExecutionContext context)
        {
            await _userService.DeleteUnconfirmedUserAsync();
        }
    }
}
